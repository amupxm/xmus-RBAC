package rbac

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type (
	//Role is a role in the system
	Role struct {
		ID          primitive.ObjectID `json:"-" bson:"_id,omiempty"`
		Name        string             `json:"name" bson:"name"`
		Permissions []Permission       `bson:"permissions"`
		CreatedAt   time.Time          `json:"created_at" bson:"createdAt"`
		UpdatedAt   time.Time          `json:"updated_at" bson:"updatedAt"`
	}
)

//CreateRole creates a new role
func (r rbac) CreateRole(ctx context.Context, roleName string) error {
	_, err := dbCollection.InsertOne(ctx, Role{
		Name: roleName,
		ID:   primitive.NewObjectID(),
	})
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return ErrDuplicatedRole
		}
		return err
	}
	return nil
}

//DeleteRole deletes a role
func (r rbac) DeleteRole(ctx context.Context, roleName string) error {
	res, err := dbCollection.DeleteOne(ctx, bson.M{"name": roleName})
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return ErrNoSuchRoleExists
		}
		return err
	}
	if res.DeletedCount == 0 {
		return ErrNoSuchRoleExists
	}
	return nil
}

//GetRole gets a role
func (r rbac) GetRole(ctx context.Context, roleName string) (*Role, error) {
	var role Role
	err := dbCollection.FindOne(ctx, bson.M{"name": roleName}).Decode(&role)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, ErrNoSuchRoleExists
		}
		return nil, err
	}
	return &role, nil
}

func (r rbac) UpdateRole(ctx context.Context, role Role) (Role, error) {
	_, err := dbCollection.UpdateOne(ctx, bson.M{"name": role.Name}, bson.M{"$set": role})
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return Role{}, ErrNoSuchRoleExists
		}
		return Role{}, err
	}
	return role, nil
}
