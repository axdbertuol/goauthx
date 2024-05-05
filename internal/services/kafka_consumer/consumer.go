package kafka_consumer

import (
	"context"
	"encoding/json"
	"log"
	"log/slog"

	"github.com/segmentio/kafka-go"
	"github.com/spf13/viper"
)

type KafkaConsumerArgs struct {
	Ctx             context.Context
	SignalCh        <-chan struct{}
	ErrCh           chan<- error
	SwitchEventFunc func(Event) error

	Brokers []string
	GroupID *string
	Topics  []string
}

func Start(args KafkaConsumerArgs) error {
	var (
		ctx             = args.Ctx
		signalCh        = args.SignalCh
		errCh           = args.ErrCh
		switchEventFunc = args.SwitchEventFunc
		brokers         = args.Brokers
		groupID         = args.GroupID
		topics          = args.Topics
	)
	// Initialize Kafka consumer
	if brokers == nil {
		brokers = []string{viper.GetString("KAFKA_BROKER_URL")}
	}
	if groupID == nil {
		str := viper.GetString("KAFKA_USER_GROUP_ID")
		groupID = &str
	}
	if topics == nil {
		topics = []string{viper.GetString("KAFKA_TOPICS")}
	}

	// Create Kafka reader
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: brokers,
		GroupID: *groupID,
		Topic:   topics[0], // Assuming only one topic
		// MinBytes: 10e3,      // 10KB
		MaxBytes: 10e6, // 10MB
	})

	// Start Kafka consumer loop
	go func() {
		slog.Debug("Starting Kafka consumer")
		for {
			select {
			case <-ctx.Done():
				return
			default:
				msg, err := reader.ReadMessage(ctx)
				if err != nil {
					log.Printf("Kafka read error: %v", err)
					errCh <- err
					continue
				}
				log.Println("Received message from Kafka: " + string(msg.Value))

				// Process Kafka message
				var event Event
				if err := json.Unmarshal(msg.Value, &event); err != nil {
					log.Printf("Error decoding Kafka message: %v", err)
					errCh <- err
					continue
				}

				if err := switchEventFunc(event); err != nil {
					log.Printf("Error handling Kafka message: %v", err)
					errCh <- err
					continue
				}
			}
		}
	}()

	// Wait for OS signal to shutdown gracefully
	<-signalCh

	// Close Kafka reader
	log.Println("Closing Kafka reader")
	if err := reader.Close(); err != nil {
		slog.Error("Kafka reader close error: %v", err)
	}
	return nil
}
