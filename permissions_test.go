package rbac

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/integration/mtest"
)

func Test_rbac_IsAllowed(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.Close()

	tests := []struct {
		roleName            string
		requestedPermission string
		permissions         []Permission
		IsAllowed           bool
	}{
		{"admin", "post.create", []Permission{Permission{Name: "post.create"}, Permission{Name: "post.delete"}}, true},
		{"admin", "post.create", []Permission{Permission{Name: "post.update"}, Permission{Name: "post.delete"}}, false},
		{"user", "post.create", []Permission{}, false},
	}
	// add some test data
	for index, tt := range tests {
		mt.Run(fmt.Sprintf("test number %d :", index), func(mt *mtest.T) {
			dbCollection = mt.Coll
			mt.AddMockResponses(mtest.CreateCursorResponse(
				1, "rbac.GetRole", mtest.FirstBatch, bson.D{{"name", tt.roleName}, {"permissions", tt.permissions}},
			))
			IsAllowed, err := rbac{}.IsAllowed(context.TODO(), tt.roleName, tt.requestedPermission)
			assert.Nil(mt.T, err)
			assert.Equal(mt.T, IsAllowed, tt.IsAllowed)
		})
	}
}

func Test_rbac_GetPermission(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.Close()

	tests := []struct {
		roleName string
		response primitive.D
	}{
		{"admin", bson.D{{"name", "admin"}, {"permissions", []Permission{Permission{Name: "post.create"}, Permission{Name: "post.delete"}}}}},
		{"end-user", bson.D{{"name", "end-user"}, {"permissions", []Permission{Permission{Name: "post.create"}, Permission{Name: "post.delete"}}}}},
		{"end-user", bson.D{{"name", "end-user"}, {"permissions", []Permission{}}}},
	}
	// add some test data
	for index, tt := range tests {
		mt.Run(fmt.Sprintf("test number %d :", index), func(mt *mtest.T) {
			dbCollection = mt.Coll
			mt.AddMockResponses(mtest.CreateCursorResponse(
				1, "rbac.GetRole", mtest.FirstBatch, tt.response,
			))
			res, err := rbac{}.GetPermission(context.TODO(), tt.roleName)
			assert.Equal(mt.T, len(tt.response[1].Value.([]Permission)), len(res))
			assert.Nil(mt.T, err)
		})
	}
}
