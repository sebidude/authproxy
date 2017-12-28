package main

import (
	"io/ioutil"

	"github.com/ghodss/yaml"
)

type TlsParams struct {
	CaFile   string `json:"caFile"`
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

type Configuration struct {
	Tls            TlsParams `json:"tls"`
	ListenAddress  string    `json:"listenAddress"`
	TargetAddress  string    `json:"targetAddress"`
	MetricsAddress string    `json:"metricsAddress"`
}

func LoadConfig(configfile string) (Configuration, error) {
	configContent, err := ioutil.ReadFile(configfile)
	if err != nil {
		return Configuration{}, err
	}

	var config Configuration
	err = yaml.Unmarshal(configContent, &config)
	if err != nil {
		return Configuration{}, err
	}

	return config, nil
}
