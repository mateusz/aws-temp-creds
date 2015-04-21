package awstempcreds

import (
	"fmt"
	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/service/sts"
	"os"
	"time"
)

type TempCredentialsProvider struct {
	Region      string
	Duration    time.Duration
	RoleARN     string
	role        *sts.AssumeRoleOutput
	nextRefresh time.Time
}

// Refresh the temporary credentials - get a new role.
func (p *TempCredentialsProvider) Refresh() error {
	stsClient := sts.New(&aws.Config{
		Region: p.Region,
	})

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	p.role, err = stsClient.AssumeRole(&sts.AssumeRoleInput{
		DurationSeconds: aws.Long(int64(p.Duration / time.Second)),
		RoleARN:         aws.String(p.RoleARN),
		RoleSessionName: aws.String(fmt.Sprintf("temp-%s-%d", hostname, time.Now().Unix())),
	})

	return err
}

// Transforms the temporary sts.Credentials stored in the role into proper aws.Credentials.
func (p *TempCredentialsProvider) Credentials() (*aws.Credentials, error) {
	if time.Now().After(p.nextRefresh) {
		err := p.Refresh()
		if err != nil {
			// Retry sooner than p.Duration.
			return nil, err
		}

		// Schedule next refresh 5 minutes before the credentials are due to expire.
		p.nextRefresh = time.Now().Add(p.Duration - (5 * time.Minute))
	}

	// Transpose the temporary sts.Credentials into aws.Credentials.
	return &aws.Credentials{
		AccessKeyID:     *p.role.Credentials.AccessKeyID,
		SecretAccessKey: *p.role.Credentials.SecretAccessKey,
		SessionToken:    *p.role.Credentials.SessionToken,
	}, nil
}
