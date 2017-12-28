// Copyright 2017 Sebastian Stauch.  All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

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

type VHost struct {
	TargetAddress string `json:"targetAddress"`
	Hostname      string `json:"hostname"`
}

type Configuration struct {
	Tls            TlsParams `json:"tls"`
	ListenAddress  string    `json:"listenAddress"`
	MetricsAddress string    `json:"metricsAddress"`
	VHosts         []struct {
		TargetAddress string `json:"targetAddress"`
		Hostname      string `json:"hostname"`
	} `json:"vHosts,inline"`
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
