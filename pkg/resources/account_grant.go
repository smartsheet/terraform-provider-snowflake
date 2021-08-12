package resources

import (
	"database/sql"

	"github.com/chanzuckerberg/terraform-provider-snowflake/pkg/snowflake"
	"github.com/chanzuckerberg/terraform-provider-snowflake/pkg/validation"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var validAccountPrivileges = NewPrivilegeSet(
	privilegeCreateRole,
	privilegeCreateUser,
	privilegeCreateWarehouse,
	privilegeCreateDatabase,
	privilegeCreateIntegration,
	privilegeManageGrants,
	privilegeMonitorUsage,
	privilegeMonitorExecution,
	privilegeExecuteTask,
	privilegeApplyMaskingPolicy,
	privilegeCreateShare,
	privilegeImportShare,
)

var accountGrantSchema = map[string]*schema.Schema{
	"privilege": {
		Type:         schema.TypeString,
		Optional:     true,
		Description:  "The privilege to grant on the account.",
		Default:      privilegeMonitorUsage,
		ValidateFunc: validation.ValidatePrivilege(validAccountPrivileges.ToList(), true),
	},
	"roles": {
		Type:        schema.TypeSet,
		Elem:        &schema.Schema{Type: schema.TypeString},
		Optional:    true,
		Description: "Grants privilege to these roles.",
	},
	"with_grant_option": {
		Type:        schema.TypeBool,
		Optional:    true,
		Description: "When this is set to true, allows the recipient role to grant the privileges to other roles.",
		Default:     false,
		ForceNew:    true,
	},
}

// AccountGrant returns a pointer to the resource representing an account grant
func AccountGrant() *TerraformGrantResource {
	return &TerraformGrantResource{
		Resource: &schema.Resource{
			Create: CreateAccountGrant,
			Read:   ReadAccountGrant,
			Delete: DeleteAccountGrant,
			Update: UpdateAccountGrant,

			Schema: accountGrantSchema,
			Importer: &schema.ResourceImporter{
				StateContext: schema.ImportStatePassthroughContext,
			},
		},
		ValidPrivs: validAccountPrivileges,
	}
}

// CreateAccountGrant implements schema.CreateFunc
func CreateAccountGrant(d *schema.ResourceData, meta interface{}) error {
	priv := d.Get("privilege").(string)
	grantOption := d.Get("with_grant_option").(bool)

	builder := snowflake.AccountGrant()

	err := createGenericGrant(d, meta, builder)
	if err != nil {
		return err
	}

	grantID := &grantID{
		ResourceName: "ACCOUNT",
		Privilege:    priv,
		GrantOption:  grantOption,
	}
	dataIDInput, err := grantID.String()
	if err != nil {
		return err
	}
	d.SetId(dataIDInput)

	return ReadAccountGrant(d, meta)
}

type accountGrant struct {
	CreatedOn   sql.RawBytes   `db:"created_on"`
	Privilege   sql.NullString `db:"privilege"`
	GrantedTo   sql.NullString `db:"granted_to"`
	GranteeName sql.NullString `db:"grantee_name"`
	Grantedby   sql.NullString `db:"granted_by"`
}

func readAccountGrants(db *sql.DB, showStatement string) ([]*accountGrant, error) {
	rows, err := snowflake.Query(db, showStatement)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	grants := make([]*accountGrant, 0)
	for rows.Next() {
		g := &accountGrant{}
		err = rows.StructScan(g)
		if err != nil {
			return nil, err
		}
		grants = append(grants, g)
	}

	return grants, nil

}

// ReadAccountGrant implements schema.ReadFunc
func ReadAccountGrant(d *schema.ResourceData, meta interface{}) error {
	grantID, err := grantIDFromString(d.Id())
	if err != nil {
		return err
	}
	err = d.Set("privilege", grantID.Privilege)
	if err != nil {
		return err
	}
	err = d.Set("with_grant_option", grantID.GrantOption)
	if err != nil {
		return err
	}

	builder := snowflake.AccountGrant()

	tfRoles := expandStringList(d.Get("roles").(*schema.Set).List())
	roles := make([]string, 0)

	grants, err := readAccountGrants(meta.(*sql.DB), builder.Show())
	if err != nil {
		return err
	}

	for _, grant := range grants {
		for _, tfRole := range tfRoles {
			if tfRole == grant.GranteeName.String {
				roles = append(roles, grant.GranteeName.String)
			}
		}
	}

	err = d.Set("roles", roles)
	if err != nil {
		return err
	}

	return nil

}

// DeleteAccountGrant implements schema.DeleteFunc
func DeleteAccountGrant(d *schema.ResourceData, meta interface{}) error {
	builder := snowflake.AccountGrant()

	return deleteGenericGrant(d, meta, builder)
}

// UpdateAccountGrant implements schema.UpdateFunc
func UpdateAccountGrant(d *schema.ResourceData, meta interface{}) error {
	// for now the only thing we can update is roles.
	// if nothing changed, nothing to update and we're done.
	if !d.HasChanges("roles") {
		return nil
	}

	rolesToAdd, rolesToRevoke := changeDiff(d, "roles")

	grantID, err := grantIDFromString(d.Id())
	if err != nil {
		return err
	}

	builder := snowflake.AccountGrant()

	// first revoke
	err = deleteGenericGrantRolesAndShares(meta, builder, grantID.Privilege, rolesToRevoke, nil)
	if err != nil {
		return err
	}

	// then add
	err = createGenericGrantRolesAndShares(meta, builder, grantID.Privilege, grantID.GrantOption, rolesToAdd, nil)
	if err != nil {
		return err
	}

	// done, refresh state
	return ReadAccountGrant(d, meta)
}
