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

func Test_rbac_CreateRole(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.Close()
	mt.Run("success", func(mt *mtest.T) {
		testTable := []struct {
			rollName string
		}{
			{"testRole"},
			{"testRole2"},
			{"testRole3"},
		}
		for _, tt := range testTable {
			dbCollection = mt.Coll
			mt.AddMockResponses(mtest.CreateSuccessResponse())
			err := rbac{}.CreateRole(context.Background(), tt.rollName)
			assert.Nil(t, err)
		}
	})
	mt.Run("duplicated error", func(mt *mtest.T) {
		testTable := []struct {
			rollName string
		}{
			{"duptest-testRole"},
			{"duptest-testRole2"},
			{"duptest-testRole3"},
		}
		for _, tt := range testTable {
			dbCollection = mt.Coll
			mt.AddMockResponses(mtest.CreateWriteErrorsResponse(mtest.WriteError{
				Index:   1,
				Code:    11000,
				Message: "duplicate key error",
			}))
			err := rbac{}.CreateRole(context.Background(), tt.rollName)
			assert.EqualError(t, err, ErrDuplicatedRole.Error())
		}
	})
}

func Test_rbac_DeleteRole(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.Close()
	mt.Run("success", func(mt *mtest.T) {
		testTable := []struct {
			rollName string
		}{
			{"testRole"},
			{"testRole2"},
			{"testRole3"},
		}
		for _, tt := range testTable {
			dbCollection = mt.Coll
			mt.AddMockResponses(bson.D{{"ok", 1}, {"acknowledged", true}, {"n", 1}})
			err := rbac{}.DeleteRole(context.Background(), tt.rollName)
			assert.Nil(t, err)
		}
	})
	mt.Run("not found error", func(mt *mtest.T) {
		testTable := []struct {
			rollName string
		}{
			{"testRole"},
			{"testRole2"},
			{"testRole3"},
		}
		for _, tt := range testTable {
			dbCollection = mt.Coll
			mt.AddMockResponses(bson.D{{"ok", 1}, {"acknowledged", true}, {"n", 0}})
			err := rbac{}.DeleteRole(context.Background(), tt.rollName)
			assert.EqualError(t, err, ErrNoSuchRoleExists.Error())
		}
	})
}

func Test_rbac_GetRole(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.Close()
	mt.Run("success", func(mt *mtest.T) {
		testTable := []struct {
			roll Role
		}{
			{roll: Role{Name: "testRole", Permissions: nil, ID: primitive.NewObjectID()}},
			{roll: Role{Name: "testRole2", Permissions: nil, ID: primitive.NewObjectID()}},
			{roll: Role{Name: "testRole3", Permissions: nil, ID: primitive.NewObjectID()}},
			{roll: Role{Name: "testRole4", Permissions: nil, ID: primitive.NewObjectID()}},
		}
		for _, tt := range testTable {
			dbCollection = mt.Coll
			mt.AddMockResponses(mtest.CreateCursorResponse(
				1, "test.test", mtest.FirstBatch, bson.D{{"_id", tt.roll.ID}, {"name", tt.roll.Name}},
			))
			role, err := rbac{}.GetRole(context.Background(), tt.roll.Name)
			assert.Nil(t, err)
			assert.Equal(t, tt.roll.Name, role.Name)
		}
	})
}

func Test_rbac_UpdateRole(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.Close()

	tests := []struct {
		data Role
		// responseData primitive.D
		wantError bool
	}{
		{Role{ID: primitive.NewObjectID(), Name: "admin", Permissions: []Permission{Permission{Name: "yeeet"}}}, false},
	}
	for index, tt := range tests {
		mt.Run(fmt.Sprintf("test num #%d", index), func(mt *mtest.T) {
			var curserResponse primitive.D
			if !tt.wantError {
				curserResponse = bson.D{{"ok", 1}, {"value", bson.D{
					{"_id", tt.data.ID},
					{"name", tt.data.Name},
					{"permissions", tt.data.Permissions},
				}}}
			}
			mt.AddMockResponses(curserResponse)
			dbCollection = mt.Coll
			res, err := rbac{}.UpdateRole(context.Background(), tt.data)
			assert.Nil(mt.T, err)
			assert.Equal(mt.T, res.ID, tt.data.ID)
		})
	}
}
