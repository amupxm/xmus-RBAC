package rbac

import (
	"context"
	"errors"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	mgoOptions "go.mongodb.org/mongo-driver/mongo/options"
)

type (
	rbac struct {
		verbose    bool
		logManager func(...interface{})
	}
	//RBAC stans for role based auth controller
	RBAC interface {
		//CreateRole creates a new role
		CreateRole(ctx context.Context, roleName string) error
		//DeleteRole deletes a role
		DeleteRole(ctx context.Context, roleName string) error
		//GetRole gets a role
		GetRole(ctx context.Context, roleName string) (*Role, error)
		//AddPermission(ctx,role,permission)
		AddPermission(ctx context.Context, role, permission string) error
		//GetPermission(ctx,role)
		GetPermission(ctx context.Context, role string) ([]Permission, error)
		//IsAllowed(ctx,role , permission)
		IsAllowed(ctx context.Context, role, permission string) (bool, error)
	}
	//Options set of objects you can pass to start xmus-RBAC
	Options struct {
		DbCollection *mongo.Collection
		Verbose      bool
		LogManager   func(...interface{})
	}
)

var (
	//ErrDuplicatedRole is an error when you want tp create role with duplicated name
	ErrDuplicatedRole = errors.New("duplicated role")
	//ErrNoSuchRoleExists is an error when you want to get a role that doesn't exist
	ErrNoSuchRoleExists = errors.New("role not exist")
	//ErrPermissionAlreadyExists is an error when you want to create a permission that already exists
	ErrPermissionAlreadyExists = errors.New("permission already exists")
)

func init() {}

var dbCollection *mongo.Collection

//New creates a new RBAC controller
func New(options *Options) RBAC {
	if options == nil {
		panic("you should pass at least db connection to options")
	}
	dbCollection = options.DbCollection
	dbCollection.Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys:    bson.D{{Key: "name", Value: 1}},
		Options: mgoOptions.Index().SetUnique(true),
	})
	return &rbac{
		verbose:    options.Verbose,
		logManager: options.LogManager,
	}
}
