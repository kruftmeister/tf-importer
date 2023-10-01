package main

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/tidwall/gjson"
	"log"
	"os"
	"time"
)

type envelope struct {
	FormatVersion      string           `json:"format_version"`
	TerraformVersion   string           `json:"terraform_version"`
	PlannedValues      json.RawMessage  `json:"planned_values"`
	ResourceChanges    []resourceChange `json:"resource_changes"`
	PriorState         json.RawMessage  `json:"prior_state"`
	Configuration      json.RawMessage  `json:"configuration"`
	RelevantAttributes json.RawMessage  `json:"relevant_attributes"`
	Timestamp          time.Time
}

type resourceChange struct {
	Address        string `json:"address"`
	Mode           string `json:"mode"`
	ChangePartType string `json:"type"`
	Name           string `json:"name"`
	ProviderName   string `json:"provider_name"`
	Change         change `json:"change"`
}

type change struct {
	Actions      []string        `json:"actions"`
	Before       json.RawMessage `json:"before"`
	After        json.RawMessage `json:"after"`
	AfterUnknown json.RawMessage `json:"after_unknown"`
}

var (
	factory   CommandFactory
	env       envelope
	accountID string
)

func init() {
	b, err := os.ReadFile("current_plan.json")
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(b, &env)
	if err != nil {
		if serr, ok := err.(*json.SyntaxError); ok {
			log.Printf("Error (%s) occurred at offset: %d\n", serr.Error(), serr.Offset)
			log.Println(string(b[0]))
		}
		log.Fatal("error unmarshalling json: ", err)
	}
	if accountID, err = getAccountIDFromAssumeRole(); err != nil {
		log.Fatal(fmt.Errorf("could not get account ID: %s", err))
	}

	factory = getDefaultFactory()
	fmt.Println("Loaded config")
}

func main() {
	restypes := make([]string, 0, len(env.ResourceChanges))
	for _, cp := range env.ResourceChanges {
		if cp.Change.Actions[0] == "create" {
			cmd, err := factory.Command(cp)
			if err != nil {
				//fmt.Println(err)
				continue
			}
			out, exerr := cmd.CombinedOutput()
			if exerr != nil {
				fmt.Println(err)
			}
			fmt.Println(string(out))

			restypes = append(restypes, cp.ChangePartType)
		}
	}
}

func getPolicyARN(accountID, name string) string {
	arn := arn.ARN{
		Partition: "aws",
		Service:   "iam",
		Region:    "",
		AccountID: accountID,
		Resource:  "policy/" + name,
	}
	return arn.String()
}

func getAccountIDFromAssumeRole() (string, error) {
	plan := gjson.ParseBytes(env.Configuration)
	assumeRoleARN := plan.Get("provider_config.aws.expressions.assume_role.0.role_arn.constant_value")
	if !arn.IsARN(assumeRoleARN.Str) {
		return "", fmt.Errorf("not an ARN: %s", assumeRoleARN.Str)
	}
	arn, err := arn.Parse(assumeRoleARN.Str)
	if err != nil {
		return "", err
	}

	return arn.AccountID, nil
}
