#!/bin/bash
set -e
set -x

export AWS_PAGER=""

CASTAI_API_URL="${CASTAI_API_URL:-https://api.cast.ai}"
CASTAI_GRPC_URL="${CASTAI_GRPC_URL:-grpc.cast.ai:443}"
CASTAI_API_GRPC_URL="${CASTAI_API_GRPC_URL:-api-grpc.cast.ai:443}"
CASTAI_KVISOR_GRPC_URL="${CASTAI_KVISOR_GRPC_URL:-kvisor.prod-master.cast.ai:443}"

kubectl get namespace castai-agent >/dev/null 2>&1
if [ $? -eq 1 ]; then
	echo "Cast AI namespace not found. Please run phase1 of the onboarding script first."
	exit 1
fi

if [ -z $CLUSTER_NAME ]; then
	echo "CLUSTER_NAME environment variable was not provided"
	exit 1
fi

if [ -z $REGION ]; then
	echo "REGION environment variable was not provided"
	exit 1
fi

if [ -z $USER_ARN ]; then
	echo "USER_ARN environment variable was not provided"
	exit 1
fi

if [ -z $CASTAI_API_TOKEN ] || [ -z $CASTAI_API_URL ] || [ -z $CASTAI_CLUSTER_ID ]; then
	echo "CASTAI_API_TOKEN, CASTAI_API_URL or CASTAI_CLUSTER_ID variables were not provided"
	exit 1
fi

if ! [ -x "$(command -v aws)" ]; then
	echo "Error: aws cli is not installed"
	exit 1
fi

if ! [ -x "$(command -v jq)" ]; then
	echo "Error: jq is not installed"
	exit 1
fi

if ! [ -x "$(command -v kubectl)" ]; then
	echo "Error: kubectl is not installed. (kubectl and helm are required to install castai-cluster-controller)"
	exit 1
fi

if ! [ -x "$(command -v helm)" ]; then
	echo "Error: helm is not installed. (kubectl and helm are required to install castai-cluster-controller)"
	exit 1
fi

if ! [ -x "$(command -v yq)" ]; then
	echo "Error: yq is not installed"
	exit 1
fi


create_security_group() {
	SG_NAME="cast-${CLUSTER_NAME}-cluster/CastNodeSecurityGroup"
	SG_ID=$(aws ec2 describe-security-groups --filters Name=vpc-id,Values=$CLUSTER_VPC Name=group-name,Values=$SG_NAME --region $REGION --query "SecurityGroups[*].GroupId" --output text)

	if [ -z $SG_ID ]; then
		echo "Creating new security group: '$SG_NAME'"
		SG_DESCRIPTION="CAST AI created security group that allows communication between CAST AI nodes"
		SG_TAGS="ResourceType=security-group,Tags=[{Key=Name,Value=${SG_NAME}},{Key=cast:cluster-id,Value=${CASTAI_CLUSTER_ID}}]"
		SG_ID=$(aws ec2 create-security-group --group-name $SG_NAME --description "${SG_DESCRIPTION}" --tag-specifications "${SG_TAGS}" --vpc-id $CLUSTER_VPC --region $REGION --output text --query 'GroupId')
	else
		echo "Security group already exists: '$SG_NAME'"
	fi

	# Add ingress and egress rules
	aws ec2 authorize-security-group-egress --group-id $SG_ID --region $REGION --protocol -1 --port all >>/dev/null 2>&1
	aws ec2 authorize-security-group-ingress --group-id $SG_ID --region $REGION --protocol -1 --port all --source-group $SG_ID >>/dev/null 2>&1 || true # ignore if rule already exist
}

json_equal() {
    if diff -q <(jq --sort-keys . <<< "$1") <(jq --sort-keys . <<< "$2") >>/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

function enable_base_components() {
  echo "Installing castai-cluster-controller."

  helm upgrade -i cluster-controller castai-helm/castai-cluster-controller -n castai-agent \
    --set castai.apiKey=$CASTAI_API_TOKEN \
    --set castai.apiURL=$CASTAI_API_URL \
    --set castai.clusterID=$CASTAI_CLUSTER_ID \
    --set autoscaling.enabled=$INSTALL_AUTOSCALER

  echo "Finished installing castai-cluster-controller."
}

function enable_autoscaler_agent() {
  echo "Installing autoscaler"

  echo "Installing autoscaler cloud components"
  echo "Fetching cluster information"
  CLUSTER=$(aws eks describe-cluster --name "$CLUSTER_NAME" --region "$REGION" --output json)
  CLUSTER_VPC=$(echo "$CLUSTER" | jq --raw-output '.cluster.resourcesVpcConfig.vpcId')

  CURRENT_CONTEXT=$(kubectl config view --minify -o jsonpath='{.clusters[].name}')
  echo "Checking current kubectl context"
  if ! [[ "$CURRENT_CONTEXT" == *"$CLUSTER_NAME"* ]]; then
  	echo "Error: the current kubectl context doesn't match the cluster. (kubectl config use-context my-cluster-name to select the correct context)"
  	exit 1
  fi

  # Get the current authentication mode
  current_auth_mode=$(aws eks describe-cluster --name $CLUSTER_NAME --region $REGION | grep authenticationMode | awk '{print $2}')
  echo "Authentication mode is $current_auth_mode"

  # Validating access to a cluster only if relevant authentication mode is used.
  if [[ "$current_auth_mode" == '"CONFIG_MAP"' || $current_auth_mode == "" ]]; then
    echo "Validating cluster access"
    if ! kubectl describe cm/aws-auth --namespace=kube-system >>/dev/null 2>&1; then
      echo "Error:'aws-auth' ConfigMap is missing; it is required to be present and accessible for this authentication mode"
      exit 1
    fi
  fi

  ROLE_NAME=cast-eks-${CLUSTER_NAME:0:30}-cluster-role-${CASTAI_CLUSTER_ID:0:8}
  ACCOUNT_NUMBER=$(aws sts get-caller-identity --output text --query 'Account')
  ARN="${REGION}:${ACCOUNT_NUMBER}"
  ARN_PARTITION="aws"
  if [[ $REGION == us-gov-* ]]; then
  	ARN_PARTITION="aws-us-gov"
  fi

  INLINE_POLICY_JSON="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"RunInstancesTagRestriction\",\"Effect\":\"Allow\",\"Action\":\"ec2:RunInstances\",\"Resource\":\"arn:${ARN_PARTITION}:ec2:${ARN}:instance/*\",\"Condition\":{\"StringEquals\":{\"aws:RequestTag/kubernetes.io/cluster/${CLUSTER_NAME}\":\"owned\"}}},{\"Sid\":\"RunInstancesVpcRestriction\",\"Effect\":\"Allow\",\"Action\":\"ec2:RunInstances\",\"Resource\":\"arn:${ARN_PARTITION}:ec2:${ARN}:subnet/*\",\"Condition\":{\"StringEquals\":{\"ec2:Vpc\":\"arn:${ARN_PARTITION}:ec2:${ARN}:vpc/${CLUSTER_VPC}\"}}},{\"Sid\":\"InstanceActionsTagRestriction\",\"Effect\":\"Allow\",\"Action\":[\"ec2:TerminateInstances\",\"ec2:StartInstances\",\"ec2:StopInstances\",\"ec2:CreateTags\"],\"Resource\":\"arn:${ARN_PARTITION}:ec2:${ARN}:instance/*\",\"Condition\":{\"StringEquals\":{\"ec2:ResourceTag/kubernetes.io/cluster/${CLUSTER_NAME}\":[\"owned\",\"shared\"]}}},{\"Sid\":\"AutoscalingActionsTagRestriction\",\"Effect\":\"Allow\",\"Action\":[\"autoscaling:UpdateAutoScalingGroup\",\"autoscaling:SuspendProcesses\",\"autoscaling:ResumeProcesses\",\"autoscaling:TerminateInstanceInAutoScalingGroup\"],\"Resource\":\"arn:${ARN_PARTITION}:autoscaling:${ARN}:autoScalingGroup:*:autoScalingGroupName/*\",\"Condition\":{\"StringEquals\":{\"autoscaling:ResourceTag/kubernetes.io/cluster/${CLUSTER_NAME}\":[\"owned\",\"shared\"]}}},{\"Sid\":\"EKS\",\"Effect\":\"Allow\",\"Action\":[\"eks:Describe*\",\"eks:List*\",\"eks:TagResource\",\"eks:UntagResource\"],\"Resource\":[\"arn:${ARN_PARTITION}:eks:${ARN}:cluster/${CLUSTER_NAME}\",\"arn:${ARN_PARTITION}:eks:${ARN}:nodegroup/${CLUSTER_NAME}/*/*\"]}]}"
  POLICY_JSON="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"PassRoleEC2\",\"Action\":\"iam:PassRole\",\"Effect\":\"Allow\",\"Resource\":\"arn:${ARN_PARTITION}:iam::*:role/*\",\"Condition\":{\"StringEquals\":{\"iam:PassedToService\":\"ec2.amazonaws.com\"}}},{\"Sid\":\"NonResourcePermissions\",\"Effect\":\"Allow\",\"Action\":[\"iam:CreateServiceLinkedRole\",\"ec2:CreateKeyPair\",\"ec2:DeleteKeyPair\",\"ec2:CreateTags\",\"ec2:ImportKeyPair\"],\"Resource\":\"*\"},{\"Sid\":\"RunInstancesPermissions\",\"Effect\":\"Allow\",\"Action\":\"ec2:RunInstances\",\"Resource\":[\"arn:${ARN_PARTITION}:ec2:*:${ACCOUNT_NUMBER}:network-interface/*\",\"arn:${ARN_PARTITION}:ec2:*:${ACCOUNT_NUMBER}:security-group/*\",\"arn:${ARN_PARTITION}:ec2:*:${ACCOUNT_NUMBER}:volume/*\",\"arn:${ARN_PARTITION}:ec2:*:${ACCOUNT_NUMBER}:key-pair/*\",\"arn:${ARN_PARTITION}:ec2:*::image/*\"]}]}"
  ASSUME_ROLE_POLICY_JSON='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"'"$USER_ARN"'"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"'"$CASTAI_CLUSTER_ID"'"}}}]}'

  if aws iam get-role --role-name $ROLE_NAME >>/dev/null 2>&1; then
  	echo "Role already exists: '$ROLE_NAME'"
  	ROLE_ARN=$(aws iam get-role --role-name $ROLE_NAME --output text --query 'Role.Arn')
  	ROLE_CURRENT_POLICY=$(aws iam get-role --role-name $ROLE_NAME  --output json --query 'Role.AssumeRolePolicyDocument')
      if ! json_equal "$ROLE_CURRENT_POLICY" "$ASSUME_ROLE_POLICY_JSON"; then
          echo "Updating $ROLE_NAME role policy"
          aws iam update-assume-role-policy --role-name $ROLE_NAME --policy-document $ASSUME_ROLE_POLICY_JSON
      else
          echo "$ROLE_NAME role policy is up to date"
      fi
  else
  	echo "Creating new role: '$ROLE_NAME'"
  	ROLE_ARN=$(aws iam create-role --role-name $ROLE_NAME --assume-role-policy-document $ASSUME_ROLE_POLICY_JSON --description "Role to manage '$CLUSTER_NAME' EKS cluster used by CAST AI" --output text --query 'Role.Arn')
  fi

  INSTANCE_PROFILE="cast-${CLUSTER_NAME:0:40}-eks-${CASTAI_CLUSTER_ID:0:8}"
  if [[ $CREATE_AWS_NODE_ROLE = "true" ]]; then
    if aws iam get-instance-profile --instance-profile-name $INSTANCE_PROFILE >>/dev/null 2>&1; then
        echo "Instance profile already exists: '$INSTANCE_PROFILE'"
        INSTANCE_ROLE_ARN=$(aws iam get-role --role-name $INSTANCE_PROFILE --output text --query 'Role.Arn')
        aws iam add-role-to-instance-profile --instance-profile-name $INSTANCE_PROFILE --role-name $INSTANCE_PROFILE >>/dev/null 2>&1 || true
    else
        ASSUME_ROLE_JSON="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":[\"ec2.amazonaws.com\"]},\"Action\":[\"sts:AssumeRole\"]}]}"

        if aws iam get-role --role-name $INSTANCE_PROFILE >>/dev/null 2>&1; then
            echo "Instance role already exists: '$INSTANCE_PROFILE'"
            INSTANCE_ROLE_ARN=$(aws iam get-role --role-name $INSTANCE_PROFILE --output text --query 'Role.Arn')
        else
            echo "Creating new instance role: '$INSTANCE_PROFILE'"
            INSTANCE_ROLE_ARN=$(aws iam create-role --role-name $INSTANCE_PROFILE --description 'EKS node instance role used by CAST AI' --assume-role-policy-document $ASSUME_ROLE_JSON --output text --query 'Role.Arn')
        fi
        # Create policy for IPv6
        IPv6_POLICY_NAME="CastEC2AssignIPv6Policy"
        IPv6_POLICY_DOCUMENT="{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"ec2:AssignIpv6Addresses\",\"Resource\": \"*\"}]}"
        EXISTING_CAST_AI_IPv6_POLICY_ARN=$(aws iam list-policies --no-cli-pager   --query "Policies[?PolicyName=='$IPv6_POLICY_NAME'].Arn" --output text)
        # Check if the policy created by EKS module exists.
        EXISTING_IPv6_POLICY_ARN=$(aws iam list-policies --no-cli-pager   --query "Policies[?PolicyName=='AmazonEKS_CNI_IPv6_Policy'].Arn" --output text)
        if [ -z "$EXISTING_IPv6_POLICY_ARN" ]; then
        # Create the policy
        if [ -z "$EXISTING_CAST_AI_IPv6_POLICY_ARN" ]; then
            echo "Policy AmazonEKS_CNI_IPv6_Policy doesn't exist creating custom CAST AI IPv6"
            echo "Creating policy $IPv6_POLICY_NAME..."
            POLICY_ARN=$(aws iam create-policy --policy-name "$IPv6_POLICY_NAME" --policy-document "$IPv6_POLICY_DOCUMENT" --query "Policy.Arn" --output text)
            IPv6_ROLE_TO_ADD=$POLICY_ARN
        else
            IPv6_ROLE_TO_ADD=$EXISTING_CAST_AI_IPv6_POLICY_ARN
            echo "Policy $EXISTING_CAST_AI_IPv6_POLICY_ARN already exists with ARN: $EXISTING_CAST_AI_IPv6_POLICY_ARN"
        fi
        else
        echo "Policy AmazonEKS_CNI_IPv6_Policy already exists with ARN: $EXISTING_IPv6_POLICY_ARN"
        IPv6_ROLE_TO_ADD=$EXISTING_IPv6_POLICY_ARN
        fi

        role_policies=(arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy $IPv6_ROLE_TO_ADD)
        echo "Attaching policies to the instance role: '$INSTANCE_PROFILE'"
        for i in "${role_policies[@]}"; do
        echo "Attaching policy $i"
            aws iam attach-role-policy --role-name $INSTANCE_PROFILE --policy-arn $i
        done
        echo "Creating new instance profile: '$INSTANCE_PROFILE'"
        aws iam create-instance-profile --instance-profile-name $INSTANCE_PROFILE >>/dev/null 2>&1
        echo "Adding role to new instance profile: '$INSTANCE_PROFILE'"
        aws iam add-role-to-instance-profile --instance-profile-name $INSTANCE_PROFILE --role-name $INSTANCE_PROFILE
    fi
  fi

  if [[ $CREATE_AWS_SECURITY_GROUP = "true" ]]; then
    create_security_group
  fi

  if [[ $CREATE_AWS_POLICIES = "true" ]]; then
    echo "Attaching policies to the role"
    POLICY_ARN="arn:aws:iam::${ACCOUNT_NUMBER}:policy/CastEKSPolicy"
    if aws iam get-policy --policy-arn $POLICY_ARN >>/dev/null 2>&1; then

        LAST_VERSION_ID=$(aws iam list-policy-versions --policy-arn $POLICY_ARN --output text --query 'Versions[0].VersionId')
        CURRENT_POLICY_CONTENT=$(aws iam get-policy-version --policy-arn $POLICY_ARN --version-id $LAST_VERSION_ID --query "PolicyVersion.Document" --output json)
        if ! json_equal "$CURRENT_POLICY_CONTENT" "$POLICY_JSON"; then
            echo "$POLICY_ARN policy already exist with outdated version"
            VERSIONS=$(aws iam list-policy-versions --policy-arn $POLICY_ARN --output text --query 'length(Versions[*])')
            if [ "$VERSIONS" -gt "4" ]; then
                OLDEST_VERSION_ID=$(aws iam list-policy-versions --policy-arn $POLICY_ARN --output text --query 'Versions[-1].VersionId')
                echo "Deleting old $POLICY_ARN policy version $OLDEST_VERSION_ID"
                aws iam delete-policy-version --policy-arn $POLICY_ARN --version-id $OLDEST_VERSION_ID
            fi
            echo "Creating new $POLICY_ARN policy version"
            aws iam create-policy-version --policy-arn $POLICY_ARN --policy-document $POLICY_JSON --set-as-default >>/dev/null 2>&1
        else
            echo "$POLICY_ARN policy already exist with newest version"
        fi
    else
        POLICY_ARN=$(aws iam create-policy --policy-name CastEKSPolicy --policy-document $POLICY_JSON --description "Policy to manage EKS cluster used by CAST AI" --output text --query 'Policy.Arn')
    fi

    policies=(arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess arn:aws:iam::aws:policy/IAMReadOnlyAccess $POLICY_ARN)
    for i in "${policies[@]}"; do
        aws iam attach-role-policy --role-name $ROLE_NAME --policy-arn $i
    done

    aws iam put-role-policy --role-name $ROLE_NAME --policy-name CastEKSRestrictedAccess --policy-document $INLINE_POLICY_JSON
  fi
  # Check if the current authentication mode matches the desired one
  if [[ $CREATE_AWS_NODE_ROLE = "true" && $current_auth_mode == *API* ]]; then
      echo "Check count of access entries for $INSTANCE_ROLE_ARN"
      COUNT=$(aws eks list-access-entries --cluster-name $CLUSTER_NAME --region $REGION | grep  $INSTANCE_ROLE_ARN| wc -l)
      if [[ $COUNT -eq 0 ]]; then
        echo "Adding access entries"
        aws eks create-access-entry --cluster-name $CLUSTER_NAME --principal-arn $INSTANCE_ROLE_ARN --type EC2_LINUX --region $REGION
      fi
  fi

  if [[ $CREATE_AWS_NODE_ROLE = "true" && "$current_auth_mode" == '"CONFIG_MAP"' || $current_auth_mode == "" ]]; then
    echo "Adding node role to cm/aws-auth: '$INSTANCE_ROLE_ARN'"
    CAST_NODE_ROLE_JSON="{\"groups\": [\"system:bootstrappers\", \"system:nodes\"], \"rolearn\": \"${INSTANCE_ROLE_ARN}\", \"username\": \"system:node:{{EC2PrivateDNSName}}\"}"
    MAP_ROLES=$(kubectl get -n kube-system cm/aws-auth -o json | jq -r '.data.mapRoles // ""')
    OUTPUT_FORMAT="yaml"
    YAML_STYLE="default"

    if [ -z "$MAP_ROLES" ]; then
      echo "mapRoles is empty. Initializing a new list."
      CURRENT_ROLES="[]"
    else
      # JSON is a valid YAML, so we can use yq to parse the mapRoles even if it is in JSON format.
      CURRENT_ROLES=$(echo "$MAP_ROLES" | yq -o json e -)
      # Decide on output format.
      if echo "$MAP_ROLES" | jq empty 2>/dev/null; then
        echo "Detected aws-auth roles format: JSON"
        OUTPUT_FORMAT="json"
        # Ensure that jq behaves consistently with yq. They must always be consistent unless jq and/or yq installations are broken.
        if ! json_equal "$(echo "$MAP_ROLES" | jq -c .)" $CURRENT_ROLES; then
          echo "jq and yq produce inconsistent output. Please check your jq and yq installations." 
          exit 1
        fi
      else
        echo "Detected aws-auth roles format: YAML"
        OUTPUT_FORMAT="yaml"
        if echo "$MAP_ROLES" | grep -q '"rolearn":' ; then
          echo "Will use double quote style"
          YAML_STYLE="double"
        fi
      fi
    fi

    if echo "$CURRENT_ROLES" | jq -e ".[] | select(.rolearn == \"${INSTANCE_ROLE_ARN}\")" >/dev/null; then
      echo "Node role already exists in cm/aws-auth"
    else
      UPDATED_ROLES_JSON=$(echo "$CURRENT_ROLES" | jq -c ". + [${CAST_NODE_ROLE_JSON}]")

      if [ "$OUTPUT_FORMAT" = "yaml" ]; then
        if [ "$YAML_STYLE" = "double" ]; then
          UPDATED_ROLES=$(echo "$UPDATED_ROLES_JSON" | yq eval -P | yq '... style="double"' -)
        else
          UPDATED_ROLES=$(echo "$UPDATED_ROLES_JSON" | yq eval -P -)
        fi
      else
        UPDATED_ROLES="$UPDATED_ROLES_JSON"
      fi
      PATCH_JSON="{\"data\":{\"mapRoles\": $(echo "$UPDATED_ROLES" | jq -sR .)}}"

      echo "Performing client/server checks for kubectl configmap patch..."
      set +e
      DRY_RUN_OUTPUT=$(kubectl patch -n kube-system cm/aws-auth --patch "$PATCH_JSON" --dry-run=client 2>&1)
      if [[ $? -ne 0 ]]; then
        echo "Client dry-run failed:"
        echo "$DRY_RUN_OUTPUT"
        echo "Aborting patch. Please, update aws-auth configmap manually with: "
        if [ "$OUTPUT_FORMAT" = "yaml" ]; then
          echo "$CAST_NODE_ROLE_JSON" | yq eval -P -
        else
          echo "$CAST_NODE_ROLE_JSON" | jq .
        fi
      else
        echo "Client dry-run passed, going to perform dry-run on server side..."
        DRY_RUN_OUTPUT=$(kubectl patch -n kube-system cm/aws-auth --patch "$PATCH_JSON" --dry-run=server 2>&1)
        if [ $? -eq 0 ]; then
          DATA_BEFORE=$(kubectl get -n kube-system cm/aws-auth -o=jsonpath='{.data}')
          DATA_AFTER=$(kubectl patch -n kube-system cm/aws-auth --patch "$PATCH_JSON" --dry-run=server -o=jsonpath='{.data}')
          # Ensure we are not deleting but adding.
          if [ "${#DATA_BEFORE}" -gt "${#DATA_AFTER}" ]; then
            echo "Server dry-run failed: patch would delete data"
            echo "Aborting patch. Please, update aws-auth configmap manually with: "
            if [ "$OUTPUT_FORMAT" = "yaml" ]; then
              echo "$CAST_NODE_ROLE_JSON" | yq eval -P -
            else
              echo "$CAST_NODE_ROLE_JSON" | jq .
            fi
          else
            echo "Server dry-run successful. Applying the patch..."
            kubectl patch -n kube-system cm/aws-auth --patch "$PATCH_JSON"
            echo "Node role added successfully to cm/aws-auth"
          fi
        else
          echo "Server dry-run failed:"
          echo "$DRY_RUN_OUTPUT"
          echo "Aborting patch. Please, update aws-auth configmap manually with: "
          if [ "$OUTPUT_FORMAT" = "yaml" ]; then
            echo "$CAST_NODE_ROLE_JSON" | yq eval -P -
          else
            echo "$CAST_NODE_ROLE_JSON" | jq .
          fi
        fi
      fi
      set -e
    fi
  fi

  echo "Installing autoscaler cluster components"

  echo "Installing castai-spot-handler."

  helm upgrade -i castai-spot-handler castai-helm/castai-spot-handler -n castai-agent \
    --set castai.apiURL=$CASTAI_API_URL \
    --set castai.clusterID=$CASTAI_CLUSTER_ID \
    --set castai.provider=aws
  echo "Finished installing castai-spot-handler."

  echo "Installing castai-evictor."
  helm upgrade -i castai-evictor castai-helm/castai-evictor -n castai-agent --set replicaCount=0
  echo "Finished installing castai-evictor."

  if [[ $INSTALL_POD_PINNER = "true" ]]; then
    echo "Installing castai-pod-pinner."
    helm upgrade -i castai-pod-pinner castai-helm/castai-pod-pinner -n castai-agent \
      --set castai.apiURL=$CASTAI_API_URL \
      --set castai.grpcURL=$CASTAI_GRPC_URL \
      --set castai.apiKey=$CASTAI_API_TOKEN \
      --set castai.clusterID=$CASTAI_CLUSTER_ID \
      --set replicaCount=0
    echo "Finished installing castai-pod-pinner."
  fi

  if [[ $INSTALL_NVIDIA_DEVICE_PLUGIN = "true" ]]; then
    echo "Installing NVIDIA device plugin required for GPU support."
    helm upgrade -i nvdp nvdp/nvidia-device-plugin -n castai-agent \
      --set-string nodeSelector."nvidia\.com/gpu"=true \
      --set \
      tolerations[0].key=CriticalAddonsOnly,tolerations[0].operator=Exists,tolerations[1].effect=NoSchedule,tolerations[1].key="nvidia\.com/gpu",tolerations[1].operator=Exists,tolerations[2].key="scheduling\.cast\.ai/spot",tolerations[2].operator=Exists,tolerations[3].key="scheduling\.cast\.ai/scoped-autoscaler",tolerations[3].operator=Exists,tolerations[4].key="scheduling\.cast\.ai/node-template",tolerations[4].operator=Exists
    echo "Finished installing NVIDIA device plugin."
  fi


  echo "Role ARN: ${ROLE_ARN}"
  API_URL="${CASTAI_API_URL}/v1/kubernetes/external-clusters/${CASTAI_CLUSTER_ID}"
  BODY='{"eks": { "assumeRoleArn": "'"$ROLE_ARN"'" }}'

  echo "Sending role ARN to CAST AI console..."
  RESPONSE=$(curl -sSL --write-out "HTTP_STATUS:%{http_code}" -X POST -H "X-API-Key: ${CASTAI_API_TOKEN}" -d "${BODY}" $API_URL)
  RESPONSE_STATUS=$(echo "$RESPONSE" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')
  RESPONSE_BODY=$(echo "$RESPONSE" | sed -e 's/HTTP_STATUS\:.*//g')

  if [[ $RESPONSE_STATUS -eq 200 ]]; then
    echo "Successfully sent."
  else
    echo "Couldn't save role ARN to CAST AI console. Try updating cluster role ARN manually."
    echo "Error details: status=$RESPONSE_STATUS content=$RESPONSE_BODY"
    exit 1
  fi
}

function enable_ai_optimizer_proxy() {
  echo "Installing AI Optimizer Proxy"

  echo "Installing castai-ai-optimizer-proxy."
  helm upgrade -i castai-ai-optimizer-proxy castai-helm/castai-ai-optimizer-proxy -n castai-agent \
    --set castai.apiKey=$CASTAI_API_TOKEN \
    --set castai.clusterID=$CASTAI_CLUSTER_ID \
    --set castai.apiURL=$CASTAI_API_URL \
    --set createNamespace=true
  echo "Finished installing castai-ai-optimizer-proxy."
}

echo "Adding helm repositories for CAST AI required charts."
helm repo add castai-helm https://castai.github.io/helm-charts
if [[ $INSTALL_AUTOSCALER = "true" && $INSTALL_NVIDIA_DEVICE_PLUGIN = "true" ]]; then
	helm repo add nvdp https://nvidia.github.io/k8s-device-plugin
	helm repo update nvdp
fi
helm repo update castai-helm
echo "Finished adding helm charts repositories."

enable_base_components

if [[ $INSTALL_AUTOSCALER = "true" ]]; then
  enable_autoscaler_agent
fi

if [[ $INSTALL_SECURITY_AGENT = "true" || "$INSTALL_NETFLOW_EXPORTER" == "true" ]]; then
  K8S_PROVIDER="eks"
    if [ -z $CASTAI_KVISOR_GRPC_URL ] || [ -z $CASTAI_API_URL ] || [ -z $CASTAI_CLUSTER_ID ]; then
    echo "CASTAI_KVISOR_GRPC_URL, CASTAI_API_URL or CASTAI_CLUSTER_ID variables were not provided"
    exit 1
  fi

  if [ -z $K8S_PROVIDER ]; then
    echo "K8S_PROVIDER is not provided"
    exit 1
  fi

  value_overrides="--set castai.grpcAddr=$CASTAI_KVISOR_GRPC_URL \
                     --set castai.apiKey=$CASTAI_API_TOKEN \
                     --set castai.clusterID=$CASTAI_CLUSTER_ID"

  if [[ $INSTALL_SECURITY_AGENT = "true" ]]; then
    value_overrides="$value_overrides \
       --set controller.extraArgs.kube-linter-enabled=true \
       --set controller.extraArgs.image-scan-enabled=true \
       --set controller.extraArgs.kube-bench-enabled=true \
       --set controller.extraArgs.kube-bench-cloud-provider=$K8S_PROVIDER"
  fi

  if [[ $INSTALL_NETFLOW_EXPORTER = "true" ]]; then
    value_overrides="$value_overrides \
       --set agent.enabled=true \
       --set agent.extraArgs.netflow-enabled=true"

    if helm status castai-egressd -n castai-agent >/dev/null 2>&1; then
      echo "Uninstalling castai-egressd (Replaced by new castai-kvisor netflow collection)."
      helm uninstall castai-egressd -n castai-agent
      echo "Finished uninstalling castai-egressd."
    fi
  fi

  echo "Installing castai-kvisor."

  helm upgrade -i castai-kvisor castai-helm/castai-kvisor -n castai-agent --reset-then-reuse-values \
    $value_overrides

  echo "Finished installing castai-kvisor."

fi

if [[ $INSTALL_AI_OPTIMIZER_PROXY = "true" ]]; then
  enable_ai_optimizer_proxy
fi

if [[ $INSTALL_GPU_METRICS_EXPORTER = "true" ]]; then
  K8S_PROVIDER="eks"
  #!/bin/bash

  ######################################################################################################
  # This script installs the gpu-metrics-exporter chart from the CAST AI helm repository.              #
  # It checks the cluster for the presence of dcgm-exporter and nv-hostengine and configures the       #
  # gpu-metrics-exporter chart accordingly.                                                            #
  # If both dcgm-exporter and nv-hostengine are present, it configures the chart to use nv-hostengine. #
  # If only dcgm-exporter is present, it configures the chart to use it.                               #
  # If neither is present, it deploys a new dcgm-exporter with an embedded nv-hostengine.              #
  # The script requires the following environment variables to be set:                                 #
  #   CASTAI_API_TOKEN - the API token for the CAST AI API                                             #
  #   CASTAI_CLUSTER_ID - the ID of the CAST AI cluster                                                #
  #   K8S_PROVIDER - the provider of the Kubernetes cluster (e.g. eks, gke, aks)                       #
  # The script also requires the helm command to be installed.                                         #
  ######################################################################################################

  set -e

  # Constants used throughout the script
  DCGM_EXPORTER_COMMAND_SUBSTRING="dcgm-exporter"
  NV_HOSTENGINE_COMMAND_SUBSTRING="nv-hostengine"
  DCGM_EXPORTER_IMAGES=("nvcr.io/nvidia/k8s/dcgm-exporter" "nvidia/dcgm-exporter", "nvidia/gke-dcgm-exporter")
  DCGM_IMAGES=("nvcr.io/nvidia/cloud-native/dcgm" "nvidia/dcgm")
  CASTAI_AGENT_NAMESPACE="castai-agent"
  CASTAI_GPU_METRICS_EXPORTER_DAEMONSET="castai-gpu-metrics-exporter"
  CASTAI_API_URL="${CASTAI_API_URL:-https://api.cast.ai}"

  # Global vars populated by the functions
  #   Which daemon set is running dcgm-exporter
  DCGM_EXPORTER_DAEMONSET=""
  DCGM_EXPORTER_NAMESPACE=""
  #   Which ds is running nv-hostengine
  NV_HOSTENGINE_DAEMONSET=""
  NV_HOSTENGINE_NAMESPACE=""

  #### Functions start here ####

  # check_pods_command - check the command of a given ds if it contains dcgm-exporter or nv-hostengine
  #                      results are stored in the global vars DCGM_EXPORTER_DAEMONSET and NV_HOSTENGINE_DAEMONSET
  check_daemonset_command() {
    namespace=$1
    ds=$2

    all_container_commands=$(kubectl -n $namespace get daemonsets -o=jsonpath-as-json='{$.spec.template.spec.containers[*].command[*]}' $ds)
    for image in $(echo $all_container_commands | tr " " "\n"); do
      if [[ $image == *$DCGM_EXPORTER_COMMAND_SUBSTRING* ]]; then
        DCGM_EXPORTER_DAEMONSET=$ds
        DCGM_EXPORTER_NAMESPACE=$namespace
      elif [[ $image == *$NV_HOSTENGINE_COMMAND_SUBSTRING* ]]; then
        NV_HOSTENGINE_DAEMONSET=$ds
        NV_HOSTENGINE_NAMESPACE=$namespace
      fi
    done
  }

  # check_pod_args - check the arguments of a given ds if it contains dcgm-exporter
  #                  results are stored in the global vars DCGM_EXPORTER_DAEMONSET
  check_pod_args() {
    namespace=$1
    ds=$2

    all_container_commands=$(kubectl -n $namespace get daemonsets -o=jsonpath-as-json='{$.spec.template.spec.containers[*].args[*]}' $ds)
    for image in $(echo $all_container_commands | tr " " "\n"); do
      if [[ $image == *$DCGM_EXPORTER_COMMAND_SUBSTRING* ]]; then
        DCGM_EXPORTER_DAEMONSET=$ds
        DCGM_EXPORTER_NAMESPACE=$namespace
      fi
    done
  }

  # check_daemonset_image - check the image of a given ds if it is for dcgm-exporter or dcgm
  check_daemonset_image() {
    namespace=$1
    ds=$2
    all_container_images=$(kubectl -n $namespace get daemonsets -o=jsonpath-as-json='{$.spec.template.spec.containers[*].image}' $ds)
    for image in $(echo $all_container_images | tr " " "\n"); do
      for required_image in "${DCGM_EXPORTER_IMAGES[@]}"; do
        if [[ $image == *$required_image* ]]; then
          DCGM_EXPORTER_DAEMONSET=$ds
          DCGM_EXPORTER_NAMESPACE=$namespace
        fi
      done
      for required_image in "${DCGM_IMAGES[@]}"; do
        if [[ $image == *$required_image* ]]; then
          NV_HOSTENGINE_DAEMONSET=$ds
          NV_HOSTENGINE_NAMESPACE=$namespace
        fi
      done
    done
  }

  # check_all_daemonsets_in_namespace - check all daemonsets in a given namespace whether they contain dcgm-exporter or nv-hostengine
  #                                     results are stored in the global vars DCGM_EXPORTER_DAEMONSET and NV_HOSTENGINE_DAEMONSET
  check_all_daemonsets_in_namespace() {
    namespace=$1
    all_ds=$(kubectl get daemonsets -n $namespace --ignore-not-found | cut -d ' ' -f 1)
    all_ds=($all_ds)
    num_ds=${#all_ds[@]}
    [[ ! -z "$DEBUG" ]] && echo "    Found $num_ds daemonsets"
    for ds in "${all_ds[@]:1}"; do
      if [[ $ds = "$CASTAI_GPU_METRICS_EXPORTER_DAEMONSET" ]]; then
        # Skip our own daemonset
        continue
      fi
      [[ ! -z "$DEBUG" ]] && echo "    Checking daemonset $ds"
      # if any of the global vars are empty, we check by image first
      if [[ -z "$DCGM_EXPORTER_DAEMONSET" ]] || [[ -z "$NV_HOSTENGINE_DAEMONSET" ]]; then
        check_daemonset_image $namespace $ds
      fi
      # if any of the global vars are still empty, we check by command
      if [[ -z "$DCGM_EXPORTER_DAEMONSET" ]] || [[ -z "$NV_HOSTENGINE_DAEMONSET" ]]; then
        check_daemonset_command $namespace $ds
      fi
      # dcgm command can be in args because command is /bin/bash -c $args
      if [[ -z "$DCGM_EXPORTER_DAEMONSET" ]]; then
        check_pod_args $namespace $ds
      # we found both dcgm-exporter and nv-hostengine, no need to look further
      fi
      if [[ ! -z "$DCGM_EXPORTER_DAEMONSET" ]] && [[ ! -z "$NV_HOSTENGINE_DAEMONSET" ]]; then
        return
      fi
    done
  }

  # unquote_string - remove quotes from a string if they are at the start or end
  unquote_string() {
    local str=$1
    temp="${str%\"}"
    temp="${temp#\"}"
    echo $temp
  }

  # find_dcgm_exporter_label_value - find the label value of the dcgm-exporter daemonset
  #                                  the label value is used to find the service name of the dcgm-exporter
  find_dcgm_exporter_label_value() {
    local namespace=$1
    local ds=$2
    label_value=$(kubectl -n $namespace get daemonsets -o=jsonpath-as-json='{$.metadata.labels.app\.kubernetes\.io\/name}' $ds | tr -d ' []\n')
    label_value=$(unquote_string $label_value)
    if [[ ! -z $label_value ]]; then
      echo "app.kubernetes.io/name:$label_value"
    else
      label_value=$(kubectl -n $namespace get daemonsets -o=jsonpath-as-json='{$.metadata.labels.app}' $ds | tr -d ' []\n')
      label_value=$(unquote_string $label_value)
      if [[ ! -z "$label_value" ]]; then
        echo "app:$label_value"
      fi
    fi
  }

  # find_dcgm_exporter_svc - find the service name of the dcgm-exporter
  find_dcgm_exporter_svc() {
    local namespace=$1
    local dcgm_exporter_label=$2
    dcgm_exporter_label=$(echo $dcgm_exporter_label | tr ':' '=')

    echo "Trying to find service $namespace $dcgm_exporter_label"
    svc_count=$(kubectl -n $namespace get svc -l $dcgm_exporter_label -o=jsonpath='{.items | length}' 2>/dev/null || echo "0")

    if [ "$svc_count" -gt "0" ]; then
      # Only access items[0] if there are items
      svc=$(kubectl -n $namespace get svc -l $dcgm_exporter_label -o=jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    else
      svc=""
    fi

    echo $svc
  }

  #### Functions end here #####

  echo "Installing castai-gpu-metrics-exporter."

  if [ -z $CASTAI_API_TOKEN ] || [ -z $CASTAI_API_URL ] || [ -z $CASTAI_CLUSTER_ID ] || [ -z $K8S_PROVIDER ]; then
    echo "CASTAI_API_TOKEN, CASTAI_API_URL, CASTAI_CLUSTER_ID, K8S_PROVIDER variables were not provided"
    exit 1
  fi

  # determine which components need to be installed and how to configure them
  echo "Checking presence of dcgm-exporter and nv-hostengine in the cluster."
  echo "Iterating through daemonsets in all namespaces."
  echo "Will take a few seconds per daemon set. Might take a few minutes"
  echo "Set the DEBUG environment variable to any value to see more details."

  [[ ! -z "$DEBUG" ]] && echo "Going through all daemon sets in all namespaces.\n"
  all_namespaces=$(kubectl get namespaces | cut -d ' ' -f 1)
  all_namespaces=($all_namespaces)
  num_namespaces=${#all_namespaces[@]}
  current_ns=0
  for ns in "${all_namespaces[@]:1}"; do
    let current_ns=current_ns+1
    [[ ! -z "$DEBUG" ]] && echo "$current_ns/$num_namespaces:  Checking namespace $ns"
    check_all_daemonsets_in_namespace $ns
    if [[ ! -z "$DCGM_EXPORTER_DAEMONSET" ]] && [[ ! -z "$NV_HOSTENGINE_DAEMONSET" ]]; then
      break
    fi
  done
  echo ""

  value_overrides="--set gpuMetricsExporter.config.CAST_API=$CASTAI_API_URL \
                   --set gpuMetricsExporter.config.CLUSTER_ID=$CASTAI_CLUSTER_ID \
                   --set castai.apiKey=$CASTAI_API_TOKEN \
                   --set provider=$K8S_PROVIDER"

  # if we found nv-hostengine, we need to configure the dcgm-exporter container in the gpu-metrics-exporter chart
  # to connect to the 5555 port of the node.
  if [ ! -z $NV_HOSTENGINE_DAEMONSET ]; then
    echo "Found nv-hostengine, configuring gpu-metrics-exporter to use it"
    value_overrides="$value_overrides \
                     --set dcgmExporter.enabled=true \
                     --set dcgmExporter.useExternalHostEngine=true"
  # if nv-hostengine does not exist but DCGM exporter exists, then we don't deploy a new DCGM exporter just
  # configure our gpu-metrics-exporter to find the existing DCGM exporter by scanning the labels
  elif [ ! -z $DCGM_EXPORTER_DAEMONSET ]; then
    echo "Found dcgm-exporter with an embedded nv-hostengine, configuring gpu-metrics-exporter to use it"
    dcgm_label=$(find_dcgm_exporter_label_value $DCGM_EXPORTER_NAMESPACE $DCGM_EXPORTER_DAEMONSET)
    [[ ! -z "$DEBUG" ]] && echo "Discovered DCGM-exporter label: $dcgm_label"
    dcgm_service_name=$(find_dcgm_exporter_svc $DCGM_EXPORTER_NAMESPACE $dcgm_label)
    [[ ! -z "$DEBUG" ]] && echo "Discovered DCGM-exporter service name: $dcgm_service_name"
    if [ ! -z $dcgm_service_name ]; then
      value_overrides="$value_overrides \
                           --set dcgmExporter.enabled=false \
                           --set dcgmExporter.config.DCGM_HOST=$dcgm_service_name.$DCGM_EXPORTER_NAMESPACE.svc.cluster.local."
    elif [ ! -z $dcgm_label ]; then
      value_overrides="$value_overrides \
                       --set dcgmExporter.enabled=false \
                       --set gpuMetricsExporter.config.DCGM_LABELS=$dcgm_label"
    else
      echo "Could not find the service name of the dcgm-exporter or a app name label. Please check the dcgm-exporter daemonset."
      exit 1
    fi
  else
    echo "DCGM exporter and nv-hostengine not found. Deploying a new DCGM exporter with an embedded nv-hostengine."
  fi

  helm upgrade -i castai-gpu-metrics-exporter castai-helm/gpu-metrics-exporter -n castai-agent \
    $value_overrides

  echo "Finished installing castai-gpu-metrics-exporter."

fi

if [[ $INSTALL_WORKLOAD_AUTOSCALER = "true" ]]; then
  K8S_PROVIDER="eks"
  WORKLOAD_AUTOSCALER_CONFIG_SOURCE="castai-cluster-controller"
  WORKLOAD_AUTOSCALER_CHART=${WORKLOAD_AUTOSCALER_CHART:-"castai-helm/castai-workload-autoscaler"}
  WORKLOAD_AUTOSCALER_EXPORTER_CHART=${WORKLOAD_AUTOSCALER_EXPORTER_CHART:-"castai-helm/castai-workload-autoscaler-exporter"}

  check_metrics_server() {
    if ! kubectl top nodes &>/dev/null; then
      echo "CAST AI workload-autoscaler requires metrics-server. Please make sure latest version is installed and running: https://artifacthub.io/packages/helm/metrics-server/metrics-server"
      exit 1
    fi
  }

  install_workload_autoscaler() {
    echo "Installing castai-workload-autoscaler."
    helm upgrade -i castai-workload-autoscaler -n castai-agent $WORKLOAD_AUTOSCALER_EXTRA_HELM_OPTS \
      --set castai.apiKeySecretRef="$WORKLOAD_AUTOSCALER_CONFIG_SOURCE" \
      --set castai.configMapRef="$WORKLOAD_AUTOSCALER_CONFIG_SOURCE" \
      "$WORKLOAD_AUTOSCALER_CHART"
    echo "Finished installing castai-workload-autoscaler."
  }

  test_workload_autoscaler_logs() {
    echo -e "Test of castai-workload-autoscaler has failed. See: https://docs.cast.ai/docs/workload-autoscaling-overview#failed-helm-test-hooks\n"
    kubectl logs -n castai-agent pod/test-castai-workload-autoscaler-verification
  }

  test_workload_autoscaler() {
    echo "Testing castai-workload-autoscaler."
    trap test_workload_autoscaler_logs INT TERM ERR
    kubectl rollout status deployment/castai-workload-autoscaler -n castai-agent --timeout=300s
    helm test castai-workload-autoscaler -n castai-agent
    echo "Finished testing castai-workload-autoscaler."
  }

  main() {
    check_metrics_server
    install_workload_autoscaler
    test_workload_autoscaler
  }

  main

fi

echo "Scaling castai-agent:"
kubectl scale deployments/castai-agent --replicas=2 --namespace castai-agent