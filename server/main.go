package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
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

func getCacheKey(ctx context.Context, req *pb.ProbeRequest) string {
	hasher := md5.New()
	str := sourceURL(ctx, req)
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		infoHash := strings.Join(md["info-hash"], "")
		filePath := strings.Join(md["file-path"], "")
		if filePath == "" {
			filePath = strings.Join(md["path"], "")
		}
		if infoHash != "" && filePath != "" {
			str = fmt.Sprintf("%s-%s", infoHash, filePath)
		}
	}
	hasher.Write([]byte(fmt.Sprintf("%s-%s", CacheKeyPrefix, str)))
	return hex.EncodeToString(hasher.Sum(nil))
}

func (s *server) Probe(ctx context.Context, req *pb.ProbeRequest) (*pb.ProbeReply, error) {
	log := log.WithField("request", req)
	log.Info("Got new probing request")
	cacheKey := getCacheKey(ctx, req)
	log = log.WithField("cacheKey", cacheKey)
	output, err := s.redis.Get(cacheKey).Result()
	if err != nil {
		log.WithError(err).Info("Failed to fetch redis cache")
		output, err = ffprobe(ctx, sourceURL(ctx, req))
		if err != nil {
			err = errors.Wrapf(err, "probing failed")
			log.WithError(err).Warn("Probing failed")
			log.Info("Setting error cache")
			s.redis.Set(cacheKey, ErrorText+err.Error(), time.Minute*60)
			err := status.Error(codes.Internal, err.Error())
			return nil, err
		}
		log.Info("Setting cache")
		s.redis.Set(cacheKey, output, time.Hour*24*7)
	} else {
		log.Info("Using cache")
	}
	if strings.HasPrefix(output, ErrorText) {
		inErr := strings.TrimPrefix(output, ErrorText)
		log.Warnf("Got cached error=%v", inErr)
		err := status.Error(codes.Internal, inErr)
		return nil, err
	}
	var rep pb.ProbeReply
	json.Unmarshal([]byte(output), &rep)
	log.WithField("reply", rep).Info("Sending reply")
	return &rep, nil
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
		log := log.WithField("addr", addr)
		l, err := net.Listen("tcp", addr)
		if err != nil {
			log.WithError(err).Error("Failed to listen")
			return err
		}
		defer l.Close()
		client := redis.NewClient(&redis.Options{
			Addr:     fmt.Sprintf("%s:%d", c.String("rH"), c.Int("rP")),
			Password: c.String("rPASS"),
			DB:       c.Int("rDB"),
		})
		defer client.Close()

		grpcError := make(chan error, 1)
		go func() {
			log.Info("Start listening")
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
			pb.RegisterContentProberServer(s, &server{redis: client})
			reflection.Register(s)
			err := s.Serve(l)
			grpcError <- err
		}()
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		select {
		case sig := <-sigs:
			log.WithField("signal", sig).Info("Got syscall")
		case err = <-grpcError:
			log.WithError(err).Error("Got GRPC error")
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
