package main

import (
	"fmt"

	"github.com/samber/oops"

	"github.com/cli-auth/cli-box/pkg/policy"
)

type PolicyCmd struct {
	List          PolicyListCmd          `cmd:"" help:"List policy scripts in the policy dir."`
	Validate      PolicyValidateCmd      `cmd:"" help:"Validate policy scripts without changing files."`
	UpdateDefault PolicyUpdateDefaultCmd `cmd:"" name:"update-default" help:"Write missing default policy scripts."`
	Create        PolicyCreateCmd        `cmd:"" help:"Create a new per-CLI policy script."`
}

type PolicyListCmd struct {
	PolicyDir string `help:"Directory containing policy scripts." default:"./policies"`
}

type PolicyValidateCmd struct {
	PolicyDir string `help:"Directory containing policy scripts." default:"./policies"`
}

type PolicyUpdateDefaultCmd struct {
	PolicyDir string `help:"Directory containing policy scripts." default:"./policies"`
}

type PolicyCreateCmd struct {
	CLI       string `arg:"" name:"cli" help:"CLI name to create a policy for." required:""`
	PolicyDir string `help:"Directory containing policy scripts." default:"./policies"`
}

func (cmd *PolicyListCmd) Run() error {
	names, err := policy.ListDir(cmd.PolicyDir)
	if err != nil {
		return err
	}
	for _, name := range names {
		fmt.Println(name)
	}
	return nil
}

func (cmd *PolicyValidateCmd) Run() error {
	if err := policy.ValidateDir(cmd.PolicyDir); err != nil {
		return err
	}
	fmt.Printf("validated %s\n", cmd.PolicyDir)
	return nil
}

func (cmd *PolicyUpdateDefaultCmd) Run() error {
	created, err := policy.UpdateDefaultPolicies(cmd.PolicyDir)
	if err != nil {
		return err
	}
	if len(created) == 0 {
		fmt.Printf("no default policy updates for %s\n", cmd.PolicyDir)
		return nil
	}
	for _, name := range created {
		fmt.Printf("created %s\n", name)
	}
	return nil
}

func (cmd *PolicyCreateCmd) Run() error {
	name, err := policy.CreatePolicy(cmd.PolicyDir, cmd.CLI)
	if err != nil {
		return err
	}
	if name == "" {
		return oops.In("policy").Errorf("policy %q was not created", cmd.CLI)
	}
	fmt.Printf("created %s\n", name)
	return nil
}
