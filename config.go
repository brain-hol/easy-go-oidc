package main

import (
	"fmt"
	"os"
	"reflect"
)

func configFromEnv(cfg interface{}, opts ...envKeyOption) error {
	val := reflect.ValueOf(cfg).Elem()
	typ := val.Type()

	var missingVars []string

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		structField := typ.Field(i)

		envTag := structField.Tag.Get("env")
		if envTag == "" {
			continue
		}

		defaultTag := structField.Tag.Get("default")

		for _, opt := range opts {
			envTag = opt(envTag)
		}
		envValue, exists := os.LookupEnv(envTag)
		if !exists && defaultTag == "" {
			missingVars = append(missingVars, envTag)
			continue
		}
		if !field.CanSet() {
			return fmt.Errorf("cannot set field %s, make sure it is exported", structField.Name)
		}
		if field.Kind() != reflect.String {
			return fmt.Errorf("unsupported kind %s for field %s, only string is supported", field.Kind(), structField.Name)
		}
		if !exists || envValue == "" {
			field.SetString(defaultTag)
		} else {
			field.SetString(envValue)
		}
	}

	if len(missingVars) > 0 {
		return fmt.Errorf("missing environment variables: %v", missingVars)
	}

	return nil
}

type envKeyOption func(string) string

func envPrefix(prefix string) envKeyOption {
	return func(key string) string {
		return prefix + key
	}
}
