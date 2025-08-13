#!/bin/bash
CREATE_AWS_NODE_ROLE=false CREATE_AWS_SECURITY_GROUP=false CREATE_AWS_POLICIES=false ./onboarding.sh
SUBNET="<>" SG_GROUP="<>" INSTANCE_PROFILE="<>" CLUSTER_ID="<>"  ./set-node-role.sh