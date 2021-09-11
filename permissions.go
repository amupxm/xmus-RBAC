package rbac

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type (
	//Permission struct
	Permission struct {
		ID        primitive.ObjectID `json:"-" bson:"_id,omiempty"`
		Name      string             `json:"name" bson:"name"`
		CreatedAt time.Time          `json:"created_at" bson:"createdAt"`
		UpdatedAt time.Time          `json:"updated_at" bson:"updatedAt"`
	}
)

//AddPermission(ctx,role,permission)
func (r rbac) AddPermission(ctx context.Context, role, permission string) error {
	roleObj, err := r.GetRole(ctx, role)
	if err != nil {
		return ErrNoSuchRoleExists
	}
	for _, p := range roleObj.Permissions {
		if p.Name == permission {
			return ErrPermissionAlreadyExists
		}
	}
	roleObj.Permissions = append(roleObj.Permissions, Permission{
		ID:   primitive.NewObjectID(),
		Name: permission,
	})
	_, err = r.UpdateRole(ctx, *roleObj)
	if err != nil {
		return err
	}
	return nil
}

//GetPermission(ctx,role)
func (r rbac) GetPermission(ctx context.Context, role string) ([]Permission, error) {
	roleObj, err := r.GetRole(ctx, role)
	if err != nil {
		return nil, ErrNoSuchRoleExists
	}
	return roleObj.Permissions, nil
}

//IsAllowed(ctx,role , permission)
func (r rbac) IsAllowed(ctx context.Context, role, permission string) (bool, error) {
	roleObj, err := r.GetRole(ctx, role)
	if err != nil {
		return false, ErrNoSuchRoleExists
	}
	for _, p := range roleObj.Permissions {
		if p.Name == permission {
			return true, nil
		}
	}
	return false, nil
}
