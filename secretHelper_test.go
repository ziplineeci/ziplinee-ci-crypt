package crypt

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncrypt(t *testing.T) {

	t.Run("ReturnsEncryptedValueWithNonceDotEncryptedStringIfPipelineAllowListIsEmpty", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		originalText := "this is my secret"
		pipelineAllowList := ""

		// act
		encryptedTextPlusNonce, err := secretHelper.Encrypt(originalText, pipelineAllowList)

		assert.Nil(t, err)
		splittedStrings := strings.Split(encryptedTextPlusNonce, ".")
		assert.Equal(t, 2, len(splittedStrings))
		assert.Equal(t, 16, len(splittedStrings[0]))
		// fmt.Println(encryptedTextPlusNonce)
	})

	t.Run("ReturnsEncryptedValueWithNonceDotEncryptedStringIfPipelineAllowListIsDefault", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		originalText := "this is my secret"
		pipelineAllowList := ".*"

		// act
		encryptedTextPlusNonce, err := secretHelper.Encrypt(originalText, pipelineAllowList)

		assert.Nil(t, err)
		splittedStrings := strings.Split(encryptedTextPlusNonce, ".")
		assert.Equal(t, 2, len(splittedStrings))
		assert.Equal(t, 16, len(splittedStrings[0]))
		// fmt.Println(encryptedTextPlusNonce)
	})

	t.Run("ReturnsEncryptedValueWithNonceDotEncryptedStringDotPipelineAllowListIfPipelineAllowListIsNonDefault", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		originalText := "this is my secret"
		pipelineAllowList := "github.com/ziplineeci/ziplinee-ci-api"

		// act
		encryptedTextPlusNonce, err := secretHelper.Encrypt(originalText, pipelineAllowList)

		assert.Nil(t, err)
		splittedStrings := strings.Split(encryptedTextPlusNonce, ".")
		assert.Equal(t, 3, len(splittedStrings))
		assert.Equal(t, 16, len(splittedStrings[0]))
		// fmt.Println(encryptedTextPlusNonce)
		// assert.Fail(t, "show me the encrypted value")
	})
}

func TestEncryptEnvelope(t *testing.T) {

	t.Run("ReturnsEncryptedValueWithNonceDotEncryptedStringInEnvelope", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		originalText := "this is my secret"
		pipelineAllowList := ""

		// act
		encryptedTextInEnvelope, err := secretHelper.EncryptEnvelope(originalText, pipelineAllowList)

		assert.Nil(t, err)
		assert.True(t, strings.HasPrefix(encryptedTextInEnvelope, "ziplinee.secret("))
		assert.True(t, strings.HasSuffix(encryptedTextInEnvelope, ")"))
	})
}

func TestDecrypt(t *testing.T) {

	t.Run("ReturnsOriginalValue", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		originalText := "this is my secret"
		encryptedTextPlusNonce := "34TwMlihi18JCWHS.bC7KcqyjxJu0bLYnnhLwyXRc1FpBdgWL861orEETEl5d"
		pipeline := "github.com/ziplineeci/ziplinee-ci-api"

		// act
		decryptedText, _, err := secretHelper.Decrypt(encryptedTextPlusNonce, pipeline)

		assert.Nil(t, err)
		assert.Equal(t, originalText, decryptedText)
	})

	t.Run("ReturnsDefaultPipelineWhiteListIfStringContainsOneDot", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		encryptedTextPlusNonce := "34TwMlihi18JCWHS.bC7KcqyjxJu0bLYnnhLwyXRc1FpBdgWL861orEETEl5d"
		pipeline := "github.com/ziplineeci/ziplinee-ci-api"

		// act
		_, pipelineAllowList, err := secretHelper.Decrypt(encryptedTextPlusNonce, pipeline)

		assert.Nil(t, err)
		assert.Equal(t, ".*", pipelineAllowList)
	})

	t.Run("ReturnsErrorIfStringDoesNotContainDot", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		encryptedTextPlusNonce := "deFTz5Bdjg6SUe29oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u"
		pipeline := "github.com/ziplineeci/ziplinee-ci-api"

		// act
		_, _, err := secretHelper.Decrypt(encryptedTextPlusNonce, pipeline)

		assert.NotNil(t, err)
	})

	t.Run("ReturnsErrorIfStringContainsMoreThan2Dots", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		encryptedTextPlusNonce := "deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTd.xHg3.7th9u"
		pipeline := "github.com/ziplineeci/ziplinee-ci-api"

		// act
		_, _, err := secretHelper.Decrypt(encryptedTextPlusNonce, pipeline)

		assert.NotNil(t, err)
	})

	t.Run("ReturnsDecryptedPipelineWhiteListIfStringContainsTwoDots", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		originalText := "this is my secret"
		encryptedTextPlusNonce := "ggyRBRZW_ofbXRgl.DdPeqg-ulQEKBuiCC_XZVscTrt4yFRxDE_u_mf8OiNtb.HtLDsVqlyEIIEueLB-bHWt1dpHAK7tmKQoHw0cKc5SzZK9Yd1Jh_K5JS0YrmKu91wJpFEDQ="
		pipeline := "github.com/ziplineeci/ziplinee-ci-api"

		// act
		decryptedText, pipelineAllowList, err := secretHelper.Decrypt(encryptedTextPlusNonce, pipeline)

		assert.Nil(t, err)
		assert.Equal(t, originalText, decryptedText)
		assert.Equal(t, "github.com/ziplineeci/ziplinee-ci-api", pipelineAllowList)
	})

	t.Run("ReturnsDecryptedPipelineWhiteListIfStringContainsTwoDotsAndPipelineMatchesRegex", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		originalText := "this is my secret"
		encryptedTextPlusNonce := "I3tNvRAhMJ7LpG0F.PKpXTn1deA7w4BOacMNRKeUJq_F3vbHJ3ZEaeYlaejsY.L6tKVShWJU3y9ByTfNBPJf9crPjfUKrzAyQJt19-9waJ9r00-i7kIg=="
		pipeline := "github.com/ziplineeci/ziplinee-ci-web"

		// act
		decryptedText, pipelineAllowList, err := secretHelper.Decrypt(encryptedTextPlusNonce, pipeline)

		assert.Nil(t, err)
		assert.Equal(t, originalText, decryptedText)
		assert.Equal(t, "github.com/ziplineeci/.+", pipelineAllowList)
	})

	t.Run("ReturnsErrorIfPipelineDoesNotMatchPipelineAllowListRegex", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		encryptedTextPlusNonce := "ggyRBRZW_ofbXRgl.DdPeqg-ulQEKBuiCC_XZVscTrt4yFRxDE_u_mf8OiNtb.HtLDsVqlyEIIEueLB-bHWt1dpHAK7tmKQoHw0cKc5SzZK9Yd1Jh_K5JS0YrmKu91wJpFEDQ="
		pipeline := "github.com/ziplineeci/ziplinee-ci-web"

		// act
		_, _, err := secretHelper.Decrypt(encryptedTextPlusNonce, pipeline)

		assert.NotNil(t, err)
	})
}

func TestDecryptEnvelope(t *testing.T) {

	t.Run("ReturnsOriginalValue", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		originalText := "this is my secret"
		encryptedTextPlusNonce := "ziplinee.secret(zHt0cZgIPoD3bAAj.3gJmp7tqixtFvIaHgyk-4BCm-gKkvtct0XutytDXY0aR.zQN7vO5h1lhHqImOjzog7AqWiLN1RXnU1EkAATTu-PE8vSIMrfGAznCwj3r0uNhY3MVYX3Y=)"
		pipeline := "github.com/ziplineeci/ziplinee-ci-api"

		// act
		decryptedText, _, err := secretHelper.DecryptEnvelope(encryptedTextPlusNonce, pipeline)

		assert.Nil(t, err)
		assert.Equal(t, originalText, decryptedText)
	})

	t.Run("ReturnsErrorIfStringDoesNotContainDot", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		encryptedTextPlusNonce := "ziplinee.secret(ah12RCso4yoZd32Vlb-wTvz9paM8wQsoV8yd33p_Htq4j0R3tJIWQJ26gI_g)"
		pipeline := "github.com/ziplineeci/ziplinee-ci-api"

		// act
		_, _, err := secretHelper.DecryptEnvelope(encryptedTextPlusNonce, pipeline)

		assert.NotNil(t, err)
	})

	t.Run("ReturnsOriginalValueIfBuilderConfigHasNoSecrets", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		builderConfigJSON := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"ziplinee-ci-builder","app-group":"ziplinee-ci","language":"golang","team":"ziplinee-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"main"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/ziplineeci/${ZIPLINEE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ZIPLINEE_BUILD_VERSION} -X main.revision=${ZIPLINEE_GIT_REVISION} -X main.branch=${ZIPLINEE_GIT_BRANCH} -X main.buildDate=${ZIPLINEE_BUILD_DATETIME}\" -o ./publish/${ZIPLINEE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-ziplinee","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["ziplinee"]}}],"Releases":null},"jobName":"build-ziplinee-ziplinee-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"ziplineeci","repoName":"ziplinee-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"${ZIPLINEE_GITHUB_API_TOKEN}"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"ziplineeci/ziplinee-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		pipeline := "github.com/ziplineeci/ziplinee-ci-api"

		// act
		decryptedText, _, err := secretHelper.DecryptEnvelope(builderConfigJSON, pipeline)

		assert.Nil(t, err)
		assert.Equal(t, builderConfigJSON, decryptedText)
	})
}

func TestDecryptAllEnvelopes(t *testing.T) {

	t.Run("ReturnsOriginalValue", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)
		builderConfigJSON := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"ziplinee-ci-builder","app-group":"ziplinee-ci","language":"golang","team":"ziplinee-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"main"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/ziplineeci/${ZIPLINEE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ZIPLINEE_BUILD_VERSION} -X main.revision=${ZIPLINEE_GIT_REVISION} -X main.branch=${ZIPLINEE_GIT_BRANCH} -X main.buildDate=${ZIPLINEE_BUILD_DATETIME}\" -o ./publish/${ZIPLINEE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-ziplinee","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["ziplinee"]}}],"Releases":null},"jobName":"build-ziplinee-ziplinee-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"ziplineeci","repoName":"ziplinee-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"ziplinee.secret(deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u)"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"ziplineeci/ziplinee-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		expectedValue := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"ziplinee-ci-builder","app-group":"ziplinee-ci","language":"golang","team":"ziplinee-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"main"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/ziplineeci/${ZIPLINEE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ZIPLINEE_BUILD_VERSION} -X main.revision=${ZIPLINEE_GIT_REVISION} -X main.branch=${ZIPLINEE_GIT_BRANCH} -X main.buildDate=${ZIPLINEE_BUILD_DATETIME}\" -o ./publish/${ZIPLINEE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-ziplinee","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["ziplinee"]}}],"Releases":null},"jobName":"build-ziplinee-ziplinee-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"ziplineeci","repoName":"ziplinee-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"this is my secret"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"ziplineeci/ziplinee-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		pipeline := "github.com/ziplineeci/ziplinee-ci-api"

		// act
		decryptedText, err := secretHelper.DecryptAllEnvelopes(builderConfigJSON, pipeline)

		assert.Nil(t, err)
		assert.Equal(t, expectedValue, decryptedText)

	})
}

func TestReencryptAllEnvelopes(t *testing.T) {

	t.Run("ReturnsReencryptedValuesAndNewKey", func(t *testing.T) {

		base64encodedKey := false
		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", base64encodedKey)
		builderConfigJSON := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"ziplinee-ci-builder","app-group":"ziplinee-ci","language":"golang","team":"ziplinee-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"main"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/ziplineeci/${ZIPLINEE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ZIPLINEE_BUILD_VERSION} -X main.revision=${ZIPLINEE_GIT_REVISION} -X main.branch=${ZIPLINEE_GIT_BRANCH} -X main.buildDate=${ZIPLINEE_BUILD_DATETIME}\" -o ./publish/${ZIPLINEE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-ziplinee","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["ziplinee"]}}],"Releases":null},"jobName":"build-ziplinee-ziplinee-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"ziplineeci","repoName":"ziplinee-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"ziplinee.secret(deFTz5Bdjg6SUe29.oPIkXbze5G9PNEWS2-ZnArl8BCqHnx4MdTdxHg37th9u)"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"ziplineeci/ziplinee-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		pipeline := "github.com/ziplineeci/ziplinee-ci-api"

		// act
		reencryptedText, key, err := secretHelper.ReencryptAllEnvelopes(builderConfigJSON, pipeline, base64encodedKey)

		assert.Nil(t, err)
		assert.Equal(t, 32, len(key))
		assert.NotEqual(t, builderConfigJSON, reencryptedText)
	})

	t.Run("ReturnsReencryptedValuesAndNewKeyEvenForPipelineRestrictedSecretsForOtherPipelines", func(t *testing.T) {

		base64encodedKey := false
		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", base64encodedKey)
		// the secret in here is restricted to github.com/ziplineeci/ziplinee-ci-api
		builderConfigJSON := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"ziplinee-ci-builder","app-group":"ziplinee-ci","language":"golang","team":"ziplinee-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"main"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/ziplineeci/${ZIPLINEE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ZIPLINEE_BUILD_VERSION} -X main.revision=${ZIPLINEE_GIT_REVISION} -X main.branch=${ZIPLINEE_GIT_BRANCH} -X main.buildDate=${ZIPLINEE_BUILD_DATETIME}\" -o ./publish/${ZIPLINEE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-ziplinee","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["ziplinee"]}}],"Releases":null},"jobName":"build-ziplinee-ziplinee-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"ziplineeci","repoName":"ziplinee-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"ziplinee.secret(DQyT78E7UTipKhYb.zItT__sV5ckZaZ5GnGAlHAQC3662JQ88A-R9bmH0ymni.34pO5K4euIobfZFPkHM7EB7mUU2-fCc_ug1GWYqBTwOpLtOfmsjpNWU7hc-qbFuIly32I-Q=)"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"ziplineeci/ziplinee-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		pipeline := "github.com/ziplineeci/ziplinee-ci-web"

		// act
		reencryptedText, key, err := secretHelper.ReencryptAllEnvelopes(builderConfigJSON, pipeline, base64encodedKey)

		assert.Nil(t, err)
		assert.Equal(t, 32, len(key))
		assert.NotEqual(t, builderConfigJSON, reencryptedText)

		secretHelper = NewSecretHelper(key, base64encodedKey)
		decryptedText, err := secretHelper.DecryptAllEnvelopes(reencryptedText, "github.com/ziplineeci/ziplinee-ci-api")
		assert.Nil(t, err)
		assert.Equal(t, `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"ziplinee-ci-builder","app-group":"ziplinee-ci","language":"golang","team":"ziplinee-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"main"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/ziplineeci/${ZIPLINEE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ZIPLINEE_BUILD_VERSION} -X main.revision=${ZIPLINEE_GIT_REVISION} -X main.branch=${ZIPLINEE_GIT_BRANCH} -X main.buildDate=${ZIPLINEE_BUILD_DATETIME}\" -o ./publish/${ZIPLINEE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-ziplinee","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["ziplinee"]}}],"Releases":null},"jobName":"build-ziplinee-ziplinee-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"ziplineeci","repoName":"ziplinee-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"this is my secret"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"ziplineeci/ziplinee-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`, decryptedText)

		_, err = secretHelper.DecryptAllEnvelopes(reencryptedText, pipeline)
		assert.NotNil(t, err)
	})

	t.Run("ReturnsReencryptedValuesAndNewKeyWithBase64EncodedKey", func(t *testing.T) {

		base64encodedKey := true
		secretHelper := NewSecretHelper("U2F6YndNZjNOWnhWVmJCcVFIZWJQY1hDcXJWbjNERHA=", base64encodedKey)
		builderConfigJSON := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"ziplinee-ci-builder","app-group":"ziplinee-ci","language":"golang","team":"ziplinee-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"main"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/ziplineeci/${ZIPLINEE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ZIPLINEE_BUILD_VERSION} -X main.revision=${ZIPLINEE_GIT_REVISION} -X main.branch=${ZIPLINEE_GIT_BRANCH} -X main.buildDate=${ZIPLINEE_BUILD_DATETIME}\" -o ./publish/${ZIPLINEE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-ziplinee","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["ziplinee"]}}],"Releases":null},"jobName":"build-ziplinee-ziplinee-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"ziplineeci","repoName":"ziplinee-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"ziplinee.secret(MpHxojAPal_XIF_K.R4_LANCK38oT_KC90NyNOEwQUDitqR9Dznf1GGmLnO4P)"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"ziplineeci/ziplinee-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		pipeline := "github.com/ziplineeci/ziplinee-ci-api"

		// act
		reencryptedText, key, err := secretHelper.ReencryptAllEnvelopes(builderConfigJSON, pipeline, base64encodedKey)

		assert.Nil(t, err)
		assert.Equal(t, 44, len(key))
		assert.NotEqual(t, builderConfigJSON, reencryptedText)
	})

	t.Run("ReturnsReencryptedValuesAndNewKeyAndDecryptsThemAfterwards", func(t *testing.T) {

		base64encodedKey := false
		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", base64encodedKey)
		builderConfigJSON := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"ziplinee-ci-builder","app-group":"ziplinee-ci","language":"golang","team":"ziplinee-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"main"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/ziplineeci/${ZIPLINEE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ZIPLINEE_BUILD_VERSION} -X main.revision=${ZIPLINEE_GIT_REVISION} -X main.branch=${ZIPLINEE_GIT_BRANCH} -X main.buildDate=${ZIPLINEE_BUILD_DATETIME}\" -o ./publish/${ZIPLINEE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-ziplinee","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["ziplinee"]}}],"Releases":null},"jobName":"build-ziplinee-ziplinee-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"ziplineeci","repoName":"ziplinee-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"ziplinee.secret(MpHxojAPal_XIF_K.R4_LANCK38oT_KC90NyNOEwQUDitqR9Dznf1GGmLnO4P)"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"ziplineeci/ziplinee-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		expectedValue := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"ziplinee-ci-builder","app-group":"ziplinee-ci","language":"golang","team":"ziplinee-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"main"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/ziplineeci/${ZIPLINEE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ZIPLINEE_BUILD_VERSION} -X main.revision=${ZIPLINEE_GIT_REVISION} -X main.branch=${ZIPLINEE_GIT_BRANCH} -X main.buildDate=${ZIPLINEE_BUILD_DATETIME}\" -o ./publish/${ZIPLINEE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-ziplinee","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["ziplinee"]}}],"Releases":null},"jobName":"build-ziplinee-ziplinee-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"ziplineeci","repoName":"ziplinee-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"this is my secret"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"ziplineeci/ziplinee-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		pipeline := "github.com/ziplineeci/ziplinee-ci-api"

		reencryptedText, key, err := secretHelper.ReencryptAllEnvelopes(builderConfigJSON, pipeline, base64encodedKey)
		secretHelper = NewSecretHelper(key, base64encodedKey)

		// act
		decryptedText, err := secretHelper.DecryptAllEnvelopes(reencryptedText, pipeline)

		assert.Nil(t, err)
		assert.Equal(t, expectedValue, decryptedText)
	})

	t.Run("ReturnsReencryptedValuesAndNewKeyAndDecryptsThemAfterwardsWithBase64EncodedKey", func(t *testing.T) {

		base64encodedKey := true
		secretHelper := NewSecretHelper("U2F6YndNZjNOWnhWVmJCcVFIZWJQY1hDcXJWbjNERHA=", base64encodedKey)
		builderConfigJSON := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"ziplinee-ci-builder","app-group":"ziplinee-ci","language":"golang","team":"ziplinee-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"main"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/ziplineeci/${ZIPLINEE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ZIPLINEE_BUILD_VERSION} -X main.revision=${ZIPLINEE_GIT_REVISION} -X main.branch=${ZIPLINEE_GIT_BRANCH} -X main.buildDate=${ZIPLINEE_BUILD_DATETIME}\" -o ./publish/${ZIPLINEE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-ziplinee","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["ziplinee"]}}],"Releases":null},"jobName":"build-ziplinee-ziplinee-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"ziplineeci","repoName":"ziplinee-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"ziplinee.secret(MpHxojAPal_XIF_K.R4_LANCK38oT_KC90NyNOEwQUDitqR9Dznf1GGmLnO4P)"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"ziplineeci/ziplinee-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		expectedValue := `{"action":"build","track":"dev","manifest":{"Builder":{"Track":"stable"},"Labels":{"app":"ziplinee-ci-builder","app-group":"ziplinee-ci","language":"golang","team":"ziplinee-team"},"Version":{"SemVer":{"Major":0,"Minor":0,"Patch":"{{auto}}","LabelTemplate":"{{branch}}","ReleaseBranch":"main"},"Custom":null},"GlobalEnvVars":null,"Pipelines":[{"Name":"git-clone","ContainerImage":"extensions/git-clone:stable","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null, "shallow": false,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":true,"Retries":0,"CustomProperties":null},{"Name":"build","ContainerImage":"golang:1.11.0-alpine3.8","Shell":"/bin/sh","WorkingDirectory":"/go/src/github.com/ziplineeci/${ZIPLINEE_LABEL_APP}","Commands":["apk --update add git","go test 'go list ./... | grep -v /vendor/'","go build -a -installsuffix cgo -ldflags \"-X main.version=${ZIPLINEE_BUILD_VERSION} -X main.revision=${ZIPLINEE_GIT_REVISION} -X main.branch=${ZIPLINEE_GIT_BRANCH} -X main.buildDate=${ZIPLINEE_BUILD_DATETIME}\" -o ./publish/${ZIPLINEE_LABEL_APP} ."],"When":"status == ''succeeded''","EnvVars":{"CGO_ENABLED":"0","DOCKER_API_VERSION":"1.38","GOOS":"linux"},"AutoInjected":false,"Retries":0,"CustomProperties":null},{"Name":"bake-ziplinee","ContainerImage":"extensions/docker:dev","Shell":"/bin/sh","WorkingDirectory":"/ziplinee-work","Commands":null,"When":"status == ''succeeded''","EnvVars":null,"AutoInjected":false,"Retries":0,"CustomProperties":{"action":"build","copy":["Dockerfile"],"path":"./publish","repositories":["ziplinee"]}}],"Releases":null},"jobName":"build-ziplinee-ziplinee-ci-builder-391855387650326531","ciServer":{"baseUrl":"https://httpstat.us/200","builderEventsUrl":"https://httpstat.us/200","postLogsUrl":"https://httpstat.us/200","apiKey":""},"buildParams":{"buildID":391855387650326531},"git":{"repoSource":"github.com","repoOwner":"ziplineeci","repoName":"ziplinee-ci-builder","repoBranch":"integration-test","repoRevision":"f394515b2a91ea69addf42e4b722442b2905e268"},"buildVersion":{"version":"0.0.0-integration-test","major":0,"minor":0,"patch":"0","autoincrement":0},"credentials":[{"name":"github-api-token","type":"github-api-token","additionalProperties":{"token":"this is my secret"}}],"trustedImages":[{"path":"extensions/docker","runDocker":true},{"path":"ziplineeci/ziplinee-ci-builder","runPrivileged":true},{"path":"golang","runDocker":true,"allowCommands":true}]}`
		pipeline := "github.com/ziplineeci/ziplinee-ci-api"

		reencryptedText, key, err := secretHelper.ReencryptAllEnvelopes(builderConfigJSON, pipeline, base64encodedKey)
		secretHelper = NewSecretHelper(key, base64encodedKey)

		// act
		decryptedText, err := secretHelper.DecryptAllEnvelopes(reencryptedText, pipeline)

		assert.Nil(t, err)
		assert.Equal(t, expectedValue, decryptedText)
	})
}

func TestGetAllSecretEnvelopes(t *testing.T) {

	t.Run("ReturnsAllEnvelopes", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)

		input := `
		ziplinee.secret(MpHxojAPal_XIF_K.R4_LANCK38oT_KC90NyNOEwQUDitqR9Dznf1GGmLnO4P)

		ziplinee.secret(n-WqaQnVu5zN8FZI.sYmyQx414B0xOYHqnTKNtaCQ7B4sIj91Q8pjYtpe83fV.ooivWEs-vV4zLY7jkSGTubrIQThCXbd-eVpZM6Bm4xUraOJsDf3pPulX1wSjVFf2OH7G-do=)
		`

		// act
		envelopes, err := secretHelper.GetAllSecretEnvelopes(input)

		assert.Nil(t, err)
		if !assert.Equal(t, 2, len(envelopes)) {
			return
		}
		assert.Equal(t, "ziplinee.secret(MpHxojAPal_XIF_K.R4_LANCK38oT_KC90NyNOEwQUDitqR9Dznf1GGmLnO4P)", envelopes[0])
		assert.Equal(t, "ziplinee.secret(n-WqaQnVu5zN8FZI.sYmyQx414B0xOYHqnTKNtaCQ7B4sIj91Q8pjYtpe83fV.ooivWEs-vV4zLY7jkSGTubrIQThCXbd-eVpZM6Bm4xUraOJsDf3pPulX1wSjVFf2OH7G-do=)", envelopes[1])
	})
}

func TestGetAllSecrets(t *testing.T) {

	t.Run("ReturnsAllEnvelopeContents", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)

		input := `
		ziplinee.secret(MpHxojAPal_XIF_K.R4_LANCK38oT_KC90NyNOEwQUDitqR9Dznf1GGmLnO4P)

		ziplinee.secret(n-WqaQnVu5zN8FZI.sYmyQx414B0xOYHqnTKNtaCQ7B4sIj91Q8pjYtpe83fV.ooivWEs-vV4zLY7jkSGTubrIQThCXbd-eVpZM6Bm4xUraOJsDf3pPulX1wSjVFf2OH7G-do=)
		`

		// act
		secrets, err := secretHelper.GetAllSecrets(input)

		assert.Nil(t, err)
		if !assert.Equal(t, 2, len(secrets)) {
			return
		}
		assert.Equal(t, "MpHxojAPal_XIF_K.R4_LANCK38oT_KC90NyNOEwQUDitqR9Dznf1GGmLnO4P", secrets[0])
		assert.Equal(t, "n-WqaQnVu5zN8FZI.sYmyQx414B0xOYHqnTKNtaCQ7B4sIj91Q8pjYtpe83fV.ooivWEs-vV4zLY7jkSGTubrIQThCXbd-eVpZM6Bm4xUraOJsDf3pPulX1wSjVFf2OH7G-do=", secrets[1])
	})
}

func TestGetAllSecretValues(t *testing.T) {

	t.Run("ReturnsAllDecryptedSecretValues", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)

		input := `
		ziplinee.secret(MpHxojAPal_XIF_K.R4_LANCK38oT_KC90NyNOEwQUDitqR9Dznf1GGmLnO4P)

		ziplinee.secret(n-WqaQnVu5zN8FZI.sYmyQx414B0xOYHqnTKNtaCQ7B4sIj91Q8pjYtpe83fV.ooivWEs-vV4zLY7jkSGTubrIQThCXbd-eVpZM6Bm4xUraOJsDf3pPulX1wSjVFf2OH7G-do=)
		`

		pipeline := "github.com/ziplineeci/ziplinee-ci-api"

		// act
		values, err := secretHelper.GetAllSecretValues(input, pipeline)

		assert.Nil(t, err)
		if !assert.Equal(t, 2, len(values)) {
			return
		}
		assert.Equal(t, "this is my secret", values[0])
		assert.Equal(t, "this is my secret", values[1])
	})

	t.Run("ReturnsErrorIfAnySecretIsNotAllowedForPipeline", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)

		input := `
		ziplinee.secret(MpHxojAPal_XIF_K.R4_LANCK38oT_KC90NyNOEwQUDitqR9Dznf1GGmLnO4P)

		ziplinee.secret(n-WqaQnVu5zN8FZI.sYmyQx414B0xOYHqnTKNtaCQ7B4sIj91Q8pjYtpe83fV.ooivWEs-vV4zLY7jkSGTubrIQThCXbd-eVpZM6Bm4xUraOJsDf3pPulX1wSjVFf2OH7G-do=)
		`

		pipeline := "github.com/ziplineeci/ziplinee-ci-web"

		// act
		values, err := secretHelper.GetAllSecretValues(input, pipeline)

		assert.NotNil(t, err)
		assert.Equal(t, 0, len(values))
	})
}

func TestGetInvalidRestrictedSecrets(t *testing.T) {
	t.Run("ReturnsNilIfAllSecretsAreGlobalOrRestrictedToCurrentPipeline", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)

		input := `
		ziplinee.secret(MpHxojAPal_XIF_K.R4_LANCK38oT_KC90NyNOEwQUDitqR9Dznf1GGmLnO4P)

		ziplinee.secret(n-WqaQnVu5zN8FZI.sYmyQx414B0xOYHqnTKNtaCQ7B4sIj91Q8pjYtpe83fV.ooivWEs-vV4zLY7jkSGTubrIQThCXbd-eVpZM6Bm4xUraOJsDf3pPulX1wSjVFf2OH7G-do=)
		`

		pipeline := "github.com/ziplineeci/ziplinee-ci-api"

		// act
		invalidSecrets, err := secretHelper.GetInvalidRestrictedSecrets(input, pipeline)

		assert.Nil(t, err)
		assert.Equal(t, 0, len(invalidSecrets))
	})

	t.Run("ReturnsErrorWithListOfSecretsRestrictedToOtherPipelines", func(t *testing.T) {

		secretHelper := NewSecretHelper("SazbwMf3NZxVVbBqQHebPcXCqrVn3DDp", false)

		input := `
		ziplinee.secret(MpHxojAPal_XIF_K.R4_LANCK38oT_KC90NyNOEwQUDitqR9Dznf1GGmLnO4P)

		ziplinee.secret(n-WqaQnVu5zN8FZI.sYmyQx414B0xOYHqnTKNtaCQ7B4sIj91Q8pjYtpe83fV.ooivWEs-vV4zLY7jkSGTubrIQThCXbd-eVpZM6Bm4xUraOJsDf3pPulX1wSjVFf2OH7G-do=)
		`

		pipeline := "github.com/ziplineeci/ziplinee-ci-web"

		// act
		invalidSecrets, err := secretHelper.GetInvalidRestrictedSecrets(input, pipeline)

		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, ErrRestrictedSecret))
		assert.Equal(t, 1, len(invalidSecrets))
		assert.Equal(t, "ziplinee.secret(n-WqaQnVu5zN8FZI.sYmyQx414B0xOYHqnTKNtaCQ7B4sIj91Q8pjYtpe83fV.ooivWEs-vV4zLY7jkSGTubrIQThCXbd-eVpZM6Bm4xUraOJsDf3pPulX1wSjVFf2OH7G-do=)", invalidSecrets[0])
	})
}
