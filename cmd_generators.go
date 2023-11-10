package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	sts2 "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/tidwall/gjson"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const (
	typeAwsCloudwatchEventRule = "aws_cloudwatch_event_rule"

	typeAwsCloudwatchLogGroup              = "aws_cloudwatch_log_group"
	typeAwsCloudwatchLogSubscriptionFilter = "aws_cloudwatch_log_subscription_filter"
	typeAwsCloudwatchMetricAlarm           = "aws_cloudwatch_metric_alarm"

	typeAwsDbEventSubscription = "aws_db_event_subscription"
	typeAwsDbInstance          = "aws_db_instance"
	typeAwsDbParameterGroup    = "aws_db_parameter_group"
	typeAwsDbSubnetGroup       = "aws_db_subnet_group"

	typeAwsIamPolicy               = "aws_iam_policy"
	typeAwsIamRole                 = "aws_iam_role"
	typeAwsIamRolePolicy           = "aws_iam_role_policy"
	typeAwsIamRolePolicyAttachment = "aws_iam_role_policy_attachment"

	typeAwsLambdaFunction   = "aws_lambda_function"
	typeAwsLambdaPermission = "aws_lambda_permission"

	typeAwsLb         = "aws_lb"
	typeAwsLbListener = "aws_lb_listener"

	typeAwsRoute53Record = "aws_route53_record"

	typeAwsSecurityGroupRule = "aws_security_group_rule"
)

type CommandFactory interface {
	Command(cp resourceChange) (*exec.Cmd, error)
}

type defaultCmdFactory struct {
	gens map[string]CommandGenerator
}

type CommandGenerator func(cp resourceChange) (*exec.Cmd, error)

const (
	cmdTerraform       = "terraform"
	cmdTerraformImport = "import"
)

var (
	errorGenNotFound = func(name string) error { return fmt.Errorf("type: %s not found", name) }
	cfg              aws.Config
	lbMapping        = make(map[string]map[string]string)
)

func init() {
	var err error
	cfg, err = config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Println(err)
		os.Exit(128)
	}
}

func (f *defaultCmdFactory) Command(cp resourceChange) (*exec.Cmd, error) {
	c, ok := f.gens[cp.ChangePartType]
	if !ok {
		return nil, errorGenNotFound(cp.ChangePartType)
	}
	return c(cp)
}

func getDefaultFactory() CommandFactory {
	f := &defaultCmdFactory{
		gens: make(map[string]CommandGenerator),
	}

	f.gens[typeAwsCloudwatchEventRule] = importAwsCloudwatchEventRule
	f.gens[typeAwsCloudwatchLogGroup] = importAwsCloudwatchLogGroup
	f.gens[typeAwsCloudwatchLogSubscriptionFilter] = importAwsCloudwatchLogSubscriptionFilter
	f.gens[typeAwsDbEventSubscription] = importAwsDbEventSubscription
	f.gens[typeAwsDbInstance] = importAwsDbInstance
	f.gens[typeAwsDbParameterGroup] = importAwsDbParameterGroup
	f.gens[typeAwsDbSubnetGroup] = importAwsDbSubnetGroup
	f.gens[typeAwsIamPolicy] = importAwsIamPolicy
	f.gens[typeAwsIamRole] = importAwsIamRole
	f.gens[typeAwsIamRolePolicy] = importAwsIamRolePolicy
	f.gens[typeAwsIamRolePolicyAttachment] = importAwsIamRolePolicyAttachment
	f.gens[typeAwsLambdaFunction] = importAwsLambdaFunction
	f.gens[typeAwsLambdaPermission] = importAwsLambdaPermission
	f.gens[typeAwsRoute53Record] = importAwsRoute53Record
	f.gens[typeAwsSecurityGroupRule] = importAwsSecurityGroupRule
	f.gens[typeAwsCloudwatchMetricAlarm] = importAwsCloudwatchMetricAlarm
	f.gens[typeAwsLbListener] = importAwsLbListener
	f.gens[typeAwsLb] = importAwsLb

	return f
}

func importAwsCloudwatchEventRule(change resourceChange) (*exec.Cmd, error) {
	plan := gjson.ParseBytes(change.Change.After)
	pathEventBusName := "event_bus_name"
	eventBusName := plan.Get(pathEventBusName)
	if !eventBusName.Exists() {
		return nil, fmt.Errorf("attribute %s not found for resource %s", pathEventBusName, change.ChangePartType)
	}
	pathName := "name"
	name := plan.Get(pathName)
	if !name.Exists() {
		return nil, fmt.Errorf("attribute %s not found for resource %s", pathName, change.ChangePartType)
	}

	identifier := fmt.Sprintf("%s/%s", eventBusName.Str, name.Str)
	return exec.Command(cmdTerraform, cmdTerraformImport, change.Address, identifier), nil
}

func importAwsCloudwatchLogGroup(change resourceChange) (*exec.Cmd, error) {
	plan := gjson.ParseBytes(change.Change.After)
	path := "name"
	name := plan.Get(path)
	if !name.Exists() {
		return nil, fmt.Errorf("attribute %s not found for resource %s", path, change.ChangePartType)
	}
	return exec.Command(cmdTerraform, cmdTerraformImport, change.Address, name.Str), nil
}

func importAwsCloudwatchLogSubscriptionFilter(change resourceChange) (*exec.Cmd, error) {
	plan := gjson.ParseBytes(change.Change.After)
	pathLGName := "log_group_name"
	lgName := plan.Get(pathLGName)
	if !lgName.Exists() {
		return nil, fmt.Errorf("attribute %s not found for resource %s", pathLGName, change.ChangePartType)
	}
	pathName := "name"
	name := plan.Get(pathName)
	if !name.Exists() {
		return nil, fmt.Errorf("attribute %s not found for resource %s", pathName, change.ChangePartType)
	}

	return exec.Command(cmdTerraform, cmdTerraformImport, change.Address, fmt.Sprintf("%s|%s", lgName, name)), nil
}

func importAwsCloudwatchMetricAlarm(change resourceChange) (*exec.Cmd, error) {
	plan := gjson.ParseBytes(change.Change.After)
	path := "alarm_name"
	alarmName := plan.Get(path)
	if !alarmName.Exists() {
		return nil, fmt.Errorf("attribute %s not found for resource %s", path, change.ChangePartType)
	}

	return exec.Command(cmdTerraform, cmdTerraformImport, change.Address, alarmName.Str), nil
}

func importAwsIamPolicy(change resourceChange) (*exec.Cmd, error) {
	plan := gjson.ParseBytes(change.Change.After)
	path := "name"
	name := plan.Get(path)
	if !name.Exists() {
		return nil, fmt.Errorf("attribute %s not found for resource %s", path, change.ChangePartType)
	}

	arn := getPolicyARN(accountID, name.Str)

	return exec.Command(cmdTerraform, cmdTerraformImport, change.Address, arn), nil
}

func importAwsIamRole(change resourceChange) (*exec.Cmd, error) {
	plan := gjson.ParseBytes(change.Change.After)
	path := "name"
	name := plan.Get(path)
	if !name.Exists() {
		return nil, fmt.Errorf("attribute %s not found for resource %s", path, change.ChangePartType)
	}

	return exec.Command(cmdTerraform, cmdTerraformImport, change.Address, name.Str), nil
}

func importAwsIamRolePolicy(change resourceChange) (*exec.Cmd, error) {
	plan := gjson.ParseBytes(change.Change.After)
	pathPolicyName := "name"
	policyName := plan.Get(pathPolicyName)
	if !policyName.Exists() {
		return nil, fmt.Errorf("attribute %s not found for resource %s", pathPolicyName, change.ChangePartType)
	}
	pathRoleName := "role"
	roleName := plan.Get(pathRoleName)
	if !roleName.Exists() {
		return nil, fmt.Errorf("attribute %s not found for resource %s", pathRoleName, change.ChangePartType)
	}

	identifier := fmt.Sprintf("%s:%s", roleName, policyName)
	return exec.Command(cmdTerraform, cmdTerraformImport, change.Address, identifier), nil
}

func importAwsIamRolePolicyAttachment(change resourceChange) (*exec.Cmd, error) {
	plan := gjson.ParseBytes(change.Change.After)
	pathPolicyArn := "policy_arn"
	policyArn := plan.Get(pathPolicyArn)
	if !policyArn.Exists() {
		return nil, fmt.Errorf("attribute %s not found for resource %s", pathPolicyArn, change.ChangePartType)
	}
	pathRoleName := "role"
	roleName := plan.Get(pathRoleName)
	if !roleName.Exists() {
		return nil, fmt.Errorf("attribute %s not found for resource %s", pathRoleName, change.ChangePartType)
	}

	identifier := fmt.Sprintf("%s/%s", roleName, policyArn)
	return exec.Command(cmdTerraform, cmdTerraformImport, change.Address, identifier), nil
}

func importAwsLambdaFunction(change resourceChange) (*exec.Cmd, error) {
	plan := gjson.ParseBytes(change.Change.After)
	path := "function_name"
	fnName := plan.Get(path)
	if !fnName.Exists() {
		return nil, fmt.Errorf("attribute %s not found for resource %s", path, change.ChangePartType)
	}

	return exec.Command(cmdTerraform, cmdTerraformImport, change.Address, fnName.Str), nil
}

func importAwsLambdaPermission(change resourceChange) (*exec.Cmd, error) {
	plan := gjson.ParseBytes(change.Change.After)
	pathFnName := "function_name"
	fnName := plan.Get(pathFnName)
	if !fnName.Exists() {
		return nil, fmt.Errorf("attribute %s not found for resource %s", pathFnName, change.ChangePartType)
	}
	pathStatementID := "statement_id"
	statementID := plan.Get(pathStatementID)
	if !statementID.Exists() {
		return nil, fmt.Errorf("attribute %s not found for resource %s", pathStatementID, change.ChangePartType)
	}

	identifier := fmt.Sprintf("%s/%s", fnName, statementID)
	return exec.Command(cmdTerraform, cmdTerraformImport, change.Address, identifier), nil
}

func importAwsRoute53Record(change resourceChange) (*exec.Cmd, error) {
	plan := gjson.ParseBytes(change.Change.After)
	pathZID := "zone_id"
	zoneID := plan.Get(pathZID)
	if !zoneID.Exists() {
		return nil, fmt.Errorf("attribute %s not found in resource %s", pathZID, change.ChangePartType)
	}
	pathName := "name"
	name := plan.Get(pathName)
	if !name.Exists() {
		return nil, fmt.Errorf("attribute %s not found in resource %s", pathName, change.ChangePartType)
	}
	pathRecType := "type"
	recType := plan.Get(pathRecType)
	if !recType.Exists() {
		return nil, fmt.Errorf("attribute %s not found in resource %s", pathRecType, change.ChangePartType)
	}

	importID := fmt.Sprintf("%s_%s_%s", zoneID, name, recType)

	return exec.Command(cmdTerraform, cmdTerraformImport, change.Address, importID), nil
}

func importAwsDbEventSubscription(change resourceChange) (*exec.Cmd, error) {
	plan := gjson.ParseBytes(change.Change.After)
	path := "name"
	name := plan.Get(path)
	if !name.Exists() {
		return nil, fmt.Errorf("attribute %s not found for resource %s", path, change.ChangePartType)
	}

	return exec.Command(cmdTerraform, cmdTerraformImport, change.Address, name.Str), nil
}

func importAwsDbInstance(change resourceChange) (*exec.Cmd, error) {
	plan := gjson.ParseBytes(change.Change.After)
	path := "identifier"
	id := plan.Get(path)
	if !id.Exists() {
		return nil, fmt.Errorf("attribute %s not found for resource %s", path, change.ChangePartType)
	}
	return exec.Command(cmdTerraform, cmdTerraformImport, change.Address, id.Str), nil
}

func importAwsDbParameterGroup(change resourceChange) (*exec.Cmd, error) {
	plan := gjson.ParseBytes(change.Change.After)
	path := "name"
	name := plan.Get(path)
	if !name.Exists() {
		return nil, fmt.Errorf("attribute %s not found for resource %s", path, change.ChangePartType)
	}

	return exec.Command(cmdTerraform, cmdTerraformImport, change.Address, name.Str), nil
}

func importAwsDbSubnetGroup(change resourceChange) (*exec.Cmd, error) {
	plan := gjson.ParseBytes(change.Change.After)
	path := "name"
	name := plan.Get(path)
	if !name.Exists() {
		return nil, fmt.Errorf("attribute %s not found for resource %s ", path, change.ChangePartType)
	}
	return exec.Command(cmdTerraform, cmdTerraformImport, change.Address, name.Str), nil
}

func importAwsSecurityGroupRule(change resourceChange) (*exec.Cmd, error) {
	plan := gjson.ParseBytes(change.Change.After)
	sgId := plan.Get("security_group_id")
	if !sgId.Exists() {
		return nil, fmt.Errorf("attribute security_group_id not found for resource %s", change.ChangePartType)
	}
	ruleType := plan.Get("type")
	if !ruleType.Exists() {
		return nil, fmt.Errorf("attribute type not found for resource %s", change.ChangePartType)
	}
	protocol := plan.Get("protocol")
	if !protocol.Exists() {
		return nil, fmt.Errorf("attribute protocol not found for resource %s", change.ChangePartType)
	}
	fromPort := plan.Get("from_port")
	if !fromPort.Exists() {
		return nil, fmt.Errorf("attribute from_port not found for resource %s", change.ChangePartType)
	}
	toPort := plan.Get("to_port")
	if !toPort.Exists() {
		return nil, fmt.Errorf("attribute to_port not found for resource %s", change.ChangePartType)
	}
	cidrBlocks := plan.Get("cidr_blocks")
	if !cidrBlocks.Exists() {
		return nil, fmt.Errorf("attribute cidr_blocks not found for resource %s", change.ChangePartType)
	}
	cidrArr := make([]string, 0, len(cidrBlocks.Array()))
	for _, c := range cidrBlocks.Array() {
		cidrArr = append(cidrArr, c.Str)
	}

	cidrCSV := strings.Join(cidrArr, "_")
	// id string format SG_TYPE_PROTOCOL_FROMPORT_TOPORT_CIDR[_CIDR...]
	identifier := fmt.Sprintf("%s_%s_%s_%s_%s_%s", sgId, ruleType, protocol, fromPort, toPort, cidrCSV)
	return exec.Command(cmdTerraform, cmdTerraformImport, change.Address, identifier), nil

}

func importAwsLb(change resourceChange) (*exec.Cmd, error) {
	plan := gjson.ParseBytes(change.Change.Before)
	arn := plan.Get("arn")

	return exec.Command(cmdTerraform, cmdTerraformImport, change.Address, arn.String()), nil
}

func importAwsLbListener(change resourceChange) (*exec.Cmd, error) {
	plan := gjson.ParseBytes(change.Change.After)
	lbArn := plan.Get("load_balancer_arn").String()

	err := prepareLBMapping(lbArn)
	if err != nil {
		return nil, err
	}

	listenerPort := strconv.Itoa(int(plan.Get("port").Int()))
	listenerArn, ok := lbMapping[lbArn][listenerPort]
	if !ok {
		return nil, fmt.Errorf("no listener found with port %s for LB %s", listenerPort, lbArn)
	}

	return exec.Command(cmdTerraform, cmdTerraformImport, change.Address, listenerArn), nil
}

func prepareLBMapping(lbArn string) error {
	listeners, ok := lbMapping[lbArn]
	if ok && len(listeners) > 0 {
		return nil
	}

	sts := sts2.NewFromConfig(cfg)
	var roleSessionName = "crufty-bar"
	arres, arerr := sts.AssumeRole(context.TODO(), &sts2.AssumeRoleInput{RoleArn: &assumeRoleARN, RoleSessionName: &roleSessionName})
	if arerr != nil {
		return fmt.Errorf("failed assuming role '%s': %s", assumeRoleARN, arerr)
	}

	prodCfg, cfgerr := config.LoadDefaultConfig(
		context.TODO(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			*arres.Credentials.AccessKeyId,
			*arres.Credentials.SecretAccessKey,
			*arres.Credentials.SessionToken,
		)))
	if cfgerr != nil {
		return fmt.Errorf("failed reloading config: %s", cfgerr)
	}
	cli := elasticloadbalancingv2.NewFromConfig(prodCfg)

	res, err := cli.DescribeListeners(context.TODO(), &elasticloadbalancingv2.DescribeListenersInput{LoadBalancerArn: &lbArn})
	if err != nil {
		return err
	}

	lbMapping[lbArn] = make(map[string]string)
	for _, lbl := range res.Listeners {
		port := strconv.Itoa(int(*lbl.Port))
		lbMapping[lbArn][port] = *lbl.ListenerArn
	}

	return nil
}
