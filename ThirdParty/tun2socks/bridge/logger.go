package bridge

import (
	"fmt"
	"sort"
	"strings"

	"github.com/xjasonlyu/tun2socks/v2/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LogSink allows Swift to receive tun2socks log entries.
type LogSink interface {
	Log(level string, message string)
}

const defaultLogLevel = "info"

// SetLogSink installs a custom zap logger that forwards entries to sink. Pass
// a nil sink to revert to zap's production logger.
func SetLogSink(sink LogSink, level string) error {
	if sink == nil {
		log.SetLogger(zap.Must(zap.NewProduction()))
		return nil
	}

	if level == "" {
		level = defaultLogLevel
	}
	minLevel, err := zapcore.ParseLevel(strings.ToLower(level))
	if err != nil {
		return err
	}

	core := &sinkCore{
		sink:     sink,
		minLevel: minLevel,
	}
	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
	log.SetLogger(logger)
	return nil
}

type sinkCore struct {
	sink     LogSink
	minLevel zapcore.Level
	fields   []zapcore.Field
}

func (c *sinkCore) Enabled(level zapcore.Level) bool {
	return level >= c.minLevel
}

func (c *sinkCore) With(fields []zapcore.Field) zapcore.Core {
	base := make([]zapcore.Field, len(c.fields))
	copy(base, c.fields)
	base = append(base, fields...)
	return &sinkCore{
		sink:     c.sink,
		minLevel: c.minLevel,
		fields:   base,
	}
}

func (c *sinkCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

func (c *sinkCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	enc := zapcore.NewMapObjectEncoder()
	for _, field := range c.fields {
		field.AddTo(enc)
	}
	for _, field := range fields {
		field.AddTo(enc)
	}

	message := ent.Message
	payload := strings.TrimSpace(message)
	if payload == "" {
		payload = ent.Level.String()
	}

	fieldMap := make(map[string]interface{}, len(enc.Fields))
	for k, v := range enc.Fields {
		fieldMap[k] = v
	}
	if len(fieldMap) > 0 {
		payload += " " + formatFields(fieldMap)
	}

	c.sink.Log(ent.Level.String(), payload)
	return nil
}

func (c *sinkCore) Sync() error { return nil }

func formatFields(values map[string]interface{}) string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var builder strings.Builder
	builder.WriteString("[")
	for i, key := range keys {
		if i > 0 {
			builder.WriteString(" ")
		}
		builder.WriteString(key)
		builder.WriteString("=")
		builder.WriteString(formatValue(values[key]))
	}
	builder.WriteString("]")
	return builder.String()
}

func formatValue(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}
