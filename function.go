// Package p contains an HTTP Cloud Function.
package p

// package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/slack-go/slack"
)

type gitHubAlertPayload struct {
	ID                  int    `json:"id"`
	AffectedRange       string `json:"affected_range"`
	AffectedPackageName string `json:"affected_package_name"`
	ExternalReference   string `json:"external_reference"`
	ExternalIdentifier  string `json:"external_identifier"`
	FixedIn             string `json:"fixed_in"`
}

type gitHubRepositoryPayload struct {
	FullName string `json:"full_name"`
}

type githubPayload struct {
	Action     string                  `json:"action,omitempty"` //create, dismiss, resolve
	Alert      gitHubAlertPayload      `json:"alert"`
	Repository gitHubRepositoryPayload `json:"repository"`
}

func buildAttachment(gh githubPayload) slack.Attachment {

	attachment := slack.Attachment{
		// Text:          "alert",
		Color:         "warning",
		Pretext:       ":warning: Security alert created! :warning:",
		AuthorName:    "sho2010",
		AuthorSubname: "sho2010",
		Title:         "Security alert(CVE link)",
		TitleLink:     gh.Alert.ExternalReference,
		Ts:            json.Number(strconv.FormatInt(time.Now().Unix(), 10)),
	}
	repository := slack.AttachmentField{
		Title: "Repository",
		Value: gh.Repository.FullName,
		Short: true,
	}

	id := slack.AttachmentField{
		Title: "Identifier",
		Value: gh.Alert.ExternalIdentifier,
		Short: true,
	}

	pkg := slack.AttachmentField{
		Title: "Affected Package Name",
		Value: gh.Alert.AffectedPackageName,
		Short: true,
	}

	version := slack.AttachmentField{
		Title: "Affected Range",
		Value: gh.Alert.AffectedRange,
		Short: true,
	}

	attachment.Fields = []slack.AttachmentField{
		repository,
		id,
		pkg,
		version,
	}

	return attachment
}

func buildSlackPayload(gh githubPayload) slack.Message {

	// Header Section
	headerText := slack.NewTextBlockObject("mrkdwn", ":warning: Security alert created!", true, false)
	headerSection := slack.NewSectionBlock(headerText, nil, nil)

	// Fields
	repo := fmt.Sprintf("*Repository:*\n`%s`", gh.Repository.FullName)
	repositoryField := slack.NewTextBlockObject("mrkdwn", repo, false, false)

	id := fmt.Sprintf("*Identifier:*\n<%s|%s>", gh.Alert.ExternalReference, gh.Alert.ExternalIdentifier)
	identifierField := slack.NewTextBlockObject("mrkdwn", id, false, false)

	pkg := fmt.Sprintf("*Affected Package Name:*\n`%s`", gh.Alert.AffectedPackageName)
	packageField := slack.NewTextBlockObject("mrkdwn", pkg, false, false)

	version := fmt.Sprintf("*Affected Range:*\n`%s`", gh.Alert.AffectedRange)
	rangeField := slack.NewTextBlockObject("mrkdwn", version, false, false)

	fieldSlice := make([]*slack.TextBlockObject, 0)
	fieldSlice = append(fieldSlice, repositoryField)
	fieldSlice = append(fieldSlice, identifierField)
	fieldSlice = append(fieldSlice, packageField)
	fieldSlice = append(fieldSlice, rangeField)

	fieldsSection := slack.NewSectionBlock(nil, fieldSlice, nil)

	msg := slack.NewBlockMessage(
		headerSection,
		fieldsSection,
	)
	return msg
}

// Github2Slack prints the JSON encoded "message" field in the body
// of the request or "Hello, World!" if there isn't one.
func Github2Slack(w http.ResponseWriter, r *http.Request) {
	var payload githubPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		fmt.Fprint(w, "Payload decode error")
		return
	}

	// TODO: なんか slack側に投げたほうがいいかも
	if payload.Action != "create" {
		return
	}

	// block対応したらこっち使う
	// buildSlackPayload(payload)

	msg := slack.WebhookMessage{
		Attachments: []slack.Attachment{buildAttachment(payload)},
	}

	err := slack.PostWebhook(os.Getenv("WEBHOOK_URL"), &msg)
	if err != nil {
		fmt.Println(err)
	}
}

func main() {
	var payload githubPayload
	data, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fmt.Println("err")
		return
	}
	json.Unmarshal(data, &payload)

	// block対応したらこっち使う
	// buildSlackPayload(payload)

	msg := slack.WebhookMessage{
		Attachments: []slack.Attachment{buildAttachment(payload)},
	}

	err = slack.PostWebhook(os.Getenv("WEBHOOK_URL"), &msg)
	if err != nil {
		fmt.Println(err)
	}
}
