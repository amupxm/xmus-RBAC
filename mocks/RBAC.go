// Code generated by mockery (devel). DO NOT EDIT.

package mocks

import (
	context "context"

	rbac "github.com/amupxm/xmus-RBAC"
	mock "github.com/stretchr/testify/mock"
)

// RBAC is an autogenerated mock type for the RBAC type
type RBAC struct {
	mock.Mock
}

// AddPermission provides a mock function with given fields: ctx, role, permission
func (_m *RBAC) AddPermission(ctx context.Context, role string, permission string) error {
	ret := _m.Called(ctx, role, permission)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, role, permission)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CreateRole provides a mock function with given fields: ctx, roleName
func (_m *RBAC) CreateRole(ctx context.Context, roleName string) error {
	ret := _m.Called(ctx, roleName)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, roleName)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteRole provides a mock function with given fields: ctx, roleName
func (_m *RBAC) DeleteRole(ctx context.Context, roleName string) error {
	ret := _m.Called(ctx, roleName)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, roleName)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetPermission provides a mock function with given fields: ctx, role
func (_m *RBAC) GetPermission(ctx context.Context, role string) ([]rbac.Permission, error) {
	ret := _m.Called(ctx, role)

	var r0 []rbac.Permission
	if rf, ok := ret.Get(0).(func(context.Context, string) []rbac.Permission); ok {
		r0 = rf(ctx, role)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]rbac.Permission)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, role)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetRole provides a mock function with given fields: ctx, roleName
func (_m *RBAC) GetRole(ctx context.Context, roleName string) (*rbac.Role, error) {
	ret := _m.Called(ctx, roleName)

	var r0 *rbac.Role
	if rf, ok := ret.Get(0).(func(context.Context, string) *rbac.Role); ok {
		r0 = rf(ctx, roleName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*rbac.Role)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, roleName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IsAllowed provides a mock function with given fields: ctx, role, permission
func (_m *RBAC) IsAllowed(ctx context.Context, role string, permission string) (bool, error) {
	ret := _m.Called(ctx, role, permission)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, string, string) bool); ok {
		r0 = rf(ctx, role, permission)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, role, permission)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
