package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"

	"github.com/go-redis/redis"
	joonix "github.com/joonix/log"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/urfave/cli"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	u "net/url"

	pb "github.com/webtor-io/content-prober/content-prober"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_logrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
)

type server struct {
	redis *redis.Client
}

const ErrorText = "ERROR"
const CacheKeyPrefix = "content-prober"

func ffprobe(ctx context.Context, url string) (string, error) {
	done := make(chan error)
	ffprobe, err := exec.LookPath("ffprobe")
	if err != nil {
		log.WithError(err).Info("Unable to find ffprobe")
		return "", err
	}
	parsedURL, err := u.Parse(url)
	if err != nil {
		log.WithField("url", url).WithError(err).Info("Unable to parse url")
		return "", err
	}
	cmdText := fmt.Sprintf("%s -show_format -show_streams -print_format json '%s'", ffprobe, parsedURL.String())
	log.WithField("cmd", cmdText).Info("Running ffprobe command")
	cmd := exec.Command(ffprobe, "-show_format", "-show_streams", "-print_format", "json", parsedURL.String())
	var bufOut bytes.Buffer
	var bufErr bytes.Buffer
	cmd.Stdout = &bufOut
	cmd.Stderr = &bufErr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	err = cmd.Start()
	if err != nil {
		log.WithError(err).Error("Unable to start ffprobe")
		return "", err
	}

	go func() { done <- cmd.Wait() }()

	select {
	case <-ctx.Done():
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		log.WithError(ctx.Err()).Error("Got context error")
		return "", ctx.Err()
	case err := <-done:
		output := bufOut.String()
		stdErr := bufErr.String()
		if err != nil {
			log.
				WithField("stderr", stdErr).WithField("stdout", output).
				WithError(err).Error("Probing failed")
			return "", err
		}
		log.WithField("output", output).Info("Probing finished")
		return output, nil
	}
}

func sourceURL(ctx context.Context, req *pb.ProbeRequest) string {
	if req.Url != "" {
		return req.Url
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		return strings.Join(md["source-url"], "")
	}
	return ""
}

func buildCacheKey(sourceURL string, infoHash string, filePath string) string {
	hasher := md5.New()
	str := sourceURL
	if infoHash != "" && filePath != "" {
		str = fmt.Sprintf("%s-%s", infoHash, filePath)
	}
	hasher.Write([]byte(fmt.Sprintf("%s-%s", CacheKeyPrefix, str)))
	return hex.EncodeToString(hasher.Sum(nil))
}

func getCacheKey(ctx context.Context, req *pb.ProbeRequest) string {
	src := sourceURL(ctx, req)
	var infoHash, filePath string
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		infoHash = strings.Join(md["info-hash"], "")
		filePath = strings.Join(md["file-path"], "")
		if filePath == "" {
			filePath = strings.Join(md["path"], "")
		}
	}
	return buildCacheKey(src, infoHash, filePath)
}

func (s *server) probeRaw(ctx context.Context, sourceURL string, infoHash string, filePath string) (string, error) {
	cacheKey := buildCacheKey(sourceURL, infoHash, filePath)
	l := log.WithField("cacheKey", cacheKey).WithField("sourceURL", sourceURL)
	output, err := s.redis.Get(cacheKey).Result()
	if err != nil {
		l.WithError(err).Info("Failed to fetch redis cache")
		output, err = ffprobe(ctx, sourceURL)
		if err != nil {
			err = errors.Wrapf(err, "probing failed")
			l.WithError(err).Warn("Probing failed")
			l.Info("Setting error cache")
			s.redis.Set(cacheKey, ErrorText+err.Error(), time.Minute*60)
			return "", err
		}
		l.Info("Setting cache")
		s.redis.Set(cacheKey, output, time.Hour*24*7)
	} else {
		l.Info("Using cache")
	}
	if strings.HasPrefix(output, ErrorText) {
		inErr := strings.TrimPrefix(output, ErrorText)
		l.Warnf("Got cached error=%v", inErr)
		return "", errors.New(inErr)
	}
	return output, nil
}

func (s *server) Probe(ctx context.Context, req *pb.ProbeRequest) (*pb.ProbeReply, error) {
	l := log.WithField("request", req)
	l.Info("Got new probing request")
	src := sourceURL(ctx, req)
	var infoHash, filePath string
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		infoHash = strings.Join(md["info-hash"], "")
		filePath = strings.Join(md["file-path"], "")
		if filePath == "" {
			filePath = strings.Join(md["path"], "")
		}
	}
	output, err := s.probeRaw(ctx, src, infoHash, filePath)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	var rep pb.ProbeReply
	json.Unmarshal([]byte(output), &rep)
	l.WithField("reply", rep).Info("Sending reply")
	return &rep, nil
}

func (s *server) handleHTTPProbe(w http.ResponseWriter, r *http.Request) {
	sourceURL := r.Header.Get("X-Source-Url")
	if sourceURL == "" {
		http.Error(w, "X-Source-Url header is required", http.StatusBadRequest)
		return
	}
	infoHash := r.Header.Get("X-Info-Hash")
	filePath := r.Header.Get("X-Path")

	l := log.WithField("sourceURL", sourceURL).WithField("infoHash", infoHash).WithField("filePath", filePath)
	l.Info("Got new HTTP probing request")

	output, err := s.probeRaw(r.Context(), sourceURL, infoHash, filePath)
	if err != nil {
		l.WithError(err).Warn("HTTP probing failed")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(output))
}

func main() {
	log.SetFormatter(&joonix.FluentdFormatter{})
	app := cli.NewApp()
	app.Name = "content-prober-server"
	app.Usage = "runs content prober"
	app.Version = "0.0.1"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "host, H",
			Usage: "listening host",
			Value: "",
		},
		cli.IntFlag{
			Name:  "port, P",
			Usage: "listening port",
			Value: 50051,
		},
		cli.IntFlag{
			Name:   "http-port",
			Usage:  "HTTP listening port",
			Value:  8080,
			EnvVar: "HTTP_PORT",
		},
		cli.IntFlag{
			Name:   "probe-port",
			Usage:  "health probe HTTP port",
			Value:  8081,
			EnvVar: "PROBE_PORT",
		},
		cli.StringFlag{
			Name:   "redis-host, rH",
			Usage:  "hostname of the redis service",
			Value:  "127.0.0.1",
			EnvVar: "REDIS_MASTER_SERVICE_HOST, REDIS_SERVICE_HOST",
		},
		cli.IntFlag{
			Name:   "redis-port, rP",
			Usage:  "port of the redis service",
			Value:  6379,
			EnvVar: "REDIS_MASTER_SERVICE_PORT, REDIS_SERVICE_PORT",
		},
		cli.IntFlag{
			Name:   "redis-db, rDB",
			Usage:  "redis db",
			Value:  0,
			EnvVar: "REDIS_DB",
		},
		cli.StringFlag{
			Name:   "redis-password, rPASS",
			Usage:  "redis password",
			Value:  "",
			EnvVar: "REDIS_PASS, REDIS_PASSWORD",
		},
	}
	app.Action = func(c *cli.Context) error {
		if c.String("redis-host") == "" {
			return errors.New("No redis host defined")
		}
		addr := fmt.Sprintf("%s:%d", c.String("host"), c.Int("port"))
		grpcLog := log.WithFields(log.Fields{})
		grpcLogger := log.WithField("addr", addr)
		l, err := net.Listen("tcp", addr)
		if err != nil {
			grpcLogger.WithError(err).Error("Failed to listen")
			return err
		}
		defer l.Close()
		client := redis.NewClient(&redis.Options{
			Addr:     fmt.Sprintf("%s:%d", c.String("rH"), c.Int("rP")),
			Password: c.String("rPASS"),
			DB:       c.Int("rDB"),
		})
		defer client.Close()

		srv := &server{redis: client}

		grpcError := make(chan error, 1)
		go func() {
			grpcLogger.Info("Start listening gRPC")
			alwaysLoggingDeciderServer := func(ctx context.Context, fullMethodName string, servingObject interface{}) bool { return true }
			s := grpc.NewServer(
				grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(
					grpc_ctxtags.StreamServerInterceptor(),
					grpc_logrus.StreamServerInterceptor(grpcLog),
					grpc_logrus.PayloadStreamServerInterceptor(grpcLog, alwaysLoggingDeciderServer),
					grpc_recovery.StreamServerInterceptor(),
				)),
				grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
					grpc_ctxtags.UnaryServerInterceptor(),
					grpc_logrus.UnaryServerInterceptor(grpcLog),
					grpc_logrus.PayloadUnaryServerInterceptor(grpcLog, alwaysLoggingDeciderServer),
					grpc_recovery.UnaryServerInterceptor(),
				)),
			)
			pb.RegisterContentProberServer(s, srv)
			reflection.Register(s)
			err := s.Serve(l)
			grpcError <- err
		}()

		httpError := make(chan error, 1)
		go func() {
			httpAddr := fmt.Sprintf("%s:%d", c.String("host"), c.Int("http-port"))
			log.WithField("addr", httpAddr).Info("Start listening HTTP")
			mux := http.NewServeMux()
			mux.HandleFunc("/", srv.handleHTTPProbe)
			err := http.ListenAndServe(httpAddr, mux)
			httpError <- err
		}()

		probeError := make(chan error, 1)
		go func() {
			probeAddr := fmt.Sprintf("%s:%d", c.String("host"), c.Int("probe-port"))
			log.WithField("addr", probeAddr).Info("Start listening health probes")
			mux := http.NewServeMux()
			mux.HandleFunc("/liveness", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			mux.HandleFunc("/readiness", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			err := http.ListenAndServe(probeAddr, mux)
			probeError <- err
		}()

		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		select {
		case sig := <-sigs:
			log.WithField("signal", sig).Info("Got syscall")
		case err = <-grpcError:
			log.WithError(err).Error("Got GRPC error")
			return err
		case err = <-httpError:
			log.WithError(err).Error("Got HTTP error")
			return err
		case err = <-probeError:
			log.WithError(err).Error("Got probe server error")
			return err
		}
		log.Info("Shutting down... at last!")
		return nil
	}
	err := app.Run(os.Args)
	if err != nil {
		log.WithError(err).Fatal("Failed to serve application")
	}
}
