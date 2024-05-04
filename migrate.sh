#! /bin/bash 

curl -sSf https://atlasgo.sh | sh

atlas migrate diff -env gorm
atlas migrate apply --env gorm --url "postgres://tester:postgres@:5433/UserCredentialss-db?search_path=public&sslmode=disable"