#!/bin/bash

function message() {
  if [ "$DEBUG" = "true" ]; then
    echo $1
  fi
}
