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
	"sync"
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
	cs "github.com/webtor-io/common-services"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	u "net/url"

	pb "github.com/webtor-io/content-prober/content-prober"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_logrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
)

// probeCache is the slice of the Redis client probeRaw uses, so that tests
// can feed a cache hit without a Redis.
type probeCache interface {
	Get(key string) *redis.StringCmd
	Set(key string, value interface{}, expiration time.Duration) *redis.StatusCmd
}

type server struct {
	redis probeCache

	mu   sync.Mutex
	runs map[string]*probeRun // ffprobe runs in flight, by cache key
}

// probeRun is one ffprobe run of a file, shared by every request for that
// file that arrives while it is in flight.
type probeRun struct {
	done    chan struct{} // closed once output and err are set
	output  string
	err     error
	waiters int // requests still waiting; guarded by server.mu
	cancel  context.CancelFunc
}

const ErrorText = "ERROR"
const CacheKeyPrefix = "content-prober"

// ffprobeMemoryLimitKiB caps the address space (ulimit -v, KiB) of every
// ffprobe run. A crafted or broken header can make ffprobe allocate whatever
// size it declares: one run reached ~1 GiB RSS, hit the pod's 1 GiB memory
// limit, and the cgroup OOM killer took the server and every neighbouring
// probe down with it. Under the cap such a file fails only its own probe,
// with an allocation error. Ordinary probes stay near 100 MiB of address
// space (97-122 MiB VmPeak, 20-43 MiB RSS in a production sample).
//
// The cap is per process. Requests for the same file share one run per
// replica (probeShared), but two different files that each need several
// hundred MiB at the same moment can still add up past the pod limit.
// ponytail: no limit on concurrent runs. One run at a time would rule that
// out, but four fifths of ffprobe wall time is spent on sources so slow
// that the caller gives up after 20 s or more, and every probe of the
// replica would queue behind those; revisit if two heavy files coincide.
const ffprobeMemoryLimitKiB = 768 * 1024

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
	// -show_chapters: a container's chapter list ("Opening", "End Credits")
	// is where a player learns when the credits begin. It costs no extra
	// reads -- the demuxer parses chapters with the rest of the header
	// whether or not they are printed -- and no consumer is disturbed: the
	// HTTP endpoint hands the JSON through as it is, and the gRPC reply is
	// unmarshalled into a struct that ignores fields it does not know.
	// Results are cached for a week, so chapters appear for a file the next
	// time it is actually probed; the cache is NOT bumped for this -- that
	// would re-probe every torrent-backed source at once.
	args := []string{"-show_format", "-show_streams", "-show_chapters", "-print_format", "json", parsedURL.String()}
	cmdText := fmt.Sprintf("%s %s", ffprobe, strings.Join(args[:len(args)-1], " ")+" '"+parsedURL.String()+"'")
	log.WithField("cmd", cmdText).Info("Running ffprobe command")
	// The limit is set by a shell that then execs ffprobe in its place, so it
	// binds the child only, not the server. ffprobe and its arguments reach
	// the shell as positional parameters ($0, $@), never as script text, so
	// nothing in the URL is interpreted by the shell. The PID stays the same
	// across exec, so the process-group kill below still reaches ffprobe. A
	// shell that refuses ulimit -v still runs ffprobe, uncapped as before.
	script := fmt.Sprintf(`ulimit -v %d; exec "$0" "$@"`, ffprobeMemoryLimitKiB)
	cmd := exec.Command("/bin/sh", append([]string{"-c", script, ffprobe}, args...)...)
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
		cache := cacheMiss
		if err != redis.Nil {
			cache = cacheError
		}
		start := time.Now()
		output, err = s.probeShared(ctx, cacheKey, sourceURL)
		observeProbeRun(err, cache, time.Since(start))
		if err != nil {
			err = errors.Wrapf(err, "probing failed")
			l.WithError(err).Warn("Probing failed")
			return "", err
		}
		return output, nil
	}
	l.Info("Using cache")
	cachedFailure := strings.HasPrefix(output, ErrorText)
	observeCacheHit(cachedFailure)
	if cachedFailure {
		inErr := strings.TrimPrefix(output, ErrorText)
		l.Warnf("Got cached error=%v", inErr)
		return "", errors.New(inErr)
	}
	return output, nil
}

// probeShared runs ffprobe for cacheKey, or joins the run already in flight
// for it, so that concurrent requests for one file start one ffprobe rather
// than one each: a file that makes ffprobe allocate hundreds of MiB, asked
// for by several callers at once, must not multiply that by the callers.
//
// The run outlives the request that started it and stops only when every
// request waiting for it has gone, so one caller hanging up does not fail
// the others. The run caches its result itself, once.
func (s *server) probeShared(ctx context.Context, cacheKey string, sourceURL string) (string, error) {
	s.mu.Lock()
	r := s.runs[cacheKey]
	if r == nil {
		runCtx, cancel := context.WithCancel(context.Background())
		r = &probeRun{done: make(chan struct{}), cancel: cancel}
		if s.runs == nil {
			s.runs = map[string]*probeRun{}
		}
		s.runs[cacheKey] = r
		go func() {
			defer cancel()
			r.output, r.err = ffprobe(runCtx, sourceURL)
			s.cacheRun(cacheKey, r.output, r.err)
			s.mu.Lock()
			if s.runs[cacheKey] == r {
				delete(s.runs, cacheKey)
			}
			s.mu.Unlock()
			close(r.done)
		}()
	}
	r.waiters++
	s.mu.Unlock()

	select {
	case <-r.done:
		return r.output, r.err
	case <-ctx.Done():
		s.mu.Lock()
		if r.waiters--; r.waiters == 0 {
			r.cancel() // nobody wants the result any more: kill ffprobe
		}
		s.mu.Unlock()
		return "", ctx.Err()
	}
}

// cacheRun stores what one ffprobe run said about the file.
func (s *server) cacheRun(cacheKey string, output string, err error) {
	l := log.WithField("cacheKey", cacheKey)
	if err != nil {
		// Only a failure of the file itself is worth remembering. A run
		// stopped because its callers hung up or ran out of time says
		// nothing about the file; cached, it would answer every other
		// caller (Watch included) "probing failed" for an hour.
		if probeOutcome(err) == outcomeError {
			l.Info("Setting error cache")
			s.redis.Set(cacheKey, ErrorText+errors.Wrapf(err, "probing failed").Error(), time.Minute*60)
		}
		return
	}
	l.Info("Setting cache")
	s.redis.Set(cacheKey, output, time.Hour*24*7)
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

// newGRPCServer builds the server with the full interceptor chain. Shared
// with the tests so that what they measure is what production runs.
func newGRPCServer(srv pb.ContentProberServer) *grpc.Server {
	grpcLog := log.WithFields(log.Fields{})
	alwaysLoggingDeciderServer := func(ctx context.Context, fullMethodName string, servingObject interface{}) bool { return true }
	// The metrics interceptor is outermost so that it observes the final
	// status, including a panic that grpc_recovery (innermost) turned into
	// codes.Internal.
	s := grpc.NewServer(
		grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(
			grpcMetrics.StreamServerInterceptor(),
			grpc_ctxtags.StreamServerInterceptor(),
			grpc_logrus.StreamServerInterceptor(grpcLog),
			grpc_logrus.PayloadStreamServerInterceptor(grpcLog, alwaysLoggingDeciderServer),
			grpc_recovery.StreamServerInterceptor(),
		)),
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			grpcMetrics.UnaryServerInterceptor(),
			grpc_ctxtags.UnaryServerInterceptor(),
			grpc_logrus.UnaryServerInterceptor(grpcLog),
			grpc_logrus.PayloadUnaryServerInterceptor(grpcLog, alwaysLoggingDeciderServer),
			grpc_recovery.UnaryServerInterceptor(),
		)),
	)
	pb.RegisterContentProberServer(s, srv)
	// Zero-valued series for every method, so a dashboard sees 0 instead of
	// "no data" until the first call. Before reflection is registered, so the
	// 17 codes x 2 reflection services are not pre-created as dead series.
	grpcMetrics.InitializeMetrics(s)
	reflection.Register(s)
	return s
}

func main() {
	log.SetFormatter(redactingFormatter{&joonix.FluentdFormatter{}})
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
	app.Flags = cs.RegisterPromFlags(app.Flags)
	app.Action = func(c *cli.Context) error {
		if c.String("redis-host") == "" {
			return errors.New("No redis host defined")
		}
		addr := fmt.Sprintf("%s:%d", c.String("host"), c.Int("port"))
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
			s := newGRPCServer(srv)
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

		// /metrics on 8083, scraped through the chart's ServiceMonitor
		promError := make(chan error, 1)
		if prom := cs.NewProm(c); prom != nil {
			defer prom.Close()
			go func() {
				promError <- prom.Serve()
			}()
		}

		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		select {
		case sig := <-sigs:
			log.WithField("signal", sig).Info("Got syscall")
		case err = <-promError:
			log.WithError(err).Error("Got Prometheus server error")
			return err
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
