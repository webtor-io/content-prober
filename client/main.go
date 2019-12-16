package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/urfave/cli"
	pb "github.com/webtor-io/content-prober/content-prober"
	"google.golang.org/grpc"
)

func main() {
	app := cli.NewApp()
	app.Name = "content-prober-cli"
	app.Usage = "interacts with content prober"
	app.Version = "0.0.1"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "host, H",
			Usage:  "listening host",
			Value:  "localhost",
			EnvVar: "CONTENT_PROBER_SERVICE_HOST, CONTENT_PROBER_HOST",
		},
		cli.IntFlag{
			Name:   "port, P",
			Usage:  "listening port",
			Value:  50051,
			EnvVar: "CONTENT_PROBER_SERVICE_PORT, CONTENT_PROBER_PORT",
		},
		cli.StringFlag{
			Name:  "url",
			Usage: "url",
		},
	}

	app.Action = func(c *cli.Context) error {
		addr := fmt.Sprintf("%s:%d", c.String("host"), c.Int("port"))
		conn, err := grpc.Dial(addr, grpc.WithInsecure())
		if err != nil {
			logrus.WithError(err).Info("dial error addr=", addr)
			return err
		}
		defer conn.Close()
		cl := pb.NewContentProberClient(conn)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		req := pb.ProbeRequest{
			Url: c.String("url"),
		}

		r, err := cl.Probe(ctx, &req)
		if err != nil {
			logrus.WithError(err).Info("error with request=", req)
			return err
		}
		logrus.Info(r)

		return nil
	}
	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
