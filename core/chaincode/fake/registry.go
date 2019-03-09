// Code generated by counterfeiter. DO NOT EDIT.
package fake

import (
	"sync"

	chaincode_test "github.com/hyperledger/fabric/core/chaincode"
)

type Registry struct {
	RegisterStub        func(*chaincode_test.Handler) error
	registerMutex       sync.RWMutex
	registerArgsForCall []struct {
		arg1 *chaincode_test.Handler
	}
	registerReturns struct {
		result1 error
	}
	registerReturnsOnCall map[int]struct {
		result1 error
	}
	ReadyStub        func(cname string)
	readyMutex       sync.RWMutex
	readyArgsForCall []struct {
		cname string
	}
	FailedStub        func(cname string, err error)
	failedMutex       sync.RWMutex
	failedArgsForCall []struct {
		cname string
		err   error
	}
	DeregisterStub        func(cname string) error
	deregisterMutex       sync.RWMutex
	deregisterArgsForCall []struct {
		cname string
	}
	deregisterReturns struct {
		result1 error
	}
	deregisterReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *Registry) Register(arg1 *chaincode_test.Handler) error {
	fake.registerMutex.Lock()
	ret, specificReturn := fake.registerReturnsOnCall[len(fake.registerArgsForCall)]
	fake.registerArgsForCall = append(fake.registerArgsForCall, struct {
		arg1 *chaincode_test.Handler
	}{arg1})
	fake.recordInvocation("Register", []interface{}{arg1})
	fake.registerMutex.Unlock()
	if fake.RegisterStub != nil {
		return fake.RegisterStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.registerReturns.result1
}

func (fake *Registry) RegisterCallCount() int {
	fake.registerMutex.RLock()
	defer fake.registerMutex.RUnlock()
	return len(fake.registerArgsForCall)
}

func (fake *Registry) RegisterArgsForCall(i int) *chaincode_test.Handler {
	fake.registerMutex.RLock()
	defer fake.registerMutex.RUnlock()
	return fake.registerArgsForCall[i].arg1
}

func (fake *Registry) RegisterReturns(result1 error) {
	fake.RegisterStub = nil
	fake.registerReturns = struct {
		result1 error
	}{result1}
}

func (fake *Registry) RegisterReturnsOnCall(i int, result1 error) {
	fake.RegisterStub = nil
	if fake.registerReturnsOnCall == nil {
		fake.registerReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.registerReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *Registry) Ready(cname string) {
	fake.readyMutex.Lock()
	fake.readyArgsForCall = append(fake.readyArgsForCall, struct {
		cname string
	}{cname})
	fake.recordInvocation("Ready", []interface{}{cname})
	fake.readyMutex.Unlock()
	if fake.ReadyStub != nil {
		fake.ReadyStub(cname)
	}
}

func (fake *Registry) ReadyCallCount() int {
	fake.readyMutex.RLock()
	defer fake.readyMutex.RUnlock()
	return len(fake.readyArgsForCall)
}

func (fake *Registry) ReadyArgsForCall(i int) string {
	fake.readyMutex.RLock()
	defer fake.readyMutex.RUnlock()
	return fake.readyArgsForCall[i].cname
}

func (fake *Registry) Failed(cname string, err error) {
	fake.failedMutex.Lock()
	fake.failedArgsForCall = append(fake.failedArgsForCall, struct {
		cname string
		err   error
	}{cname, err})
	fake.recordInvocation("Failed", []interface{}{cname, err})
	fake.failedMutex.Unlock()
	if fake.FailedStub != nil {
		fake.FailedStub(cname, err)
	}
}

func (fake *Registry) FailedCallCount() int {
	fake.failedMutex.RLock()
	defer fake.failedMutex.RUnlock()
	return len(fake.failedArgsForCall)
}

func (fake *Registry) FailedArgsForCall(i int) (string, error) {
	fake.failedMutex.RLock()
	defer fake.failedMutex.RUnlock()
	return fake.failedArgsForCall[i].cname, fake.failedArgsForCall[i].err
}

func (fake *Registry) Deregister(cname string) error {
	fake.deregisterMutex.Lock()
	ret, specificReturn := fake.deregisterReturnsOnCall[len(fake.deregisterArgsForCall)]
	fake.deregisterArgsForCall = append(fake.deregisterArgsForCall, struct {
		cname string
	}{cname})
	fake.recordInvocation("Deregister", []interface{}{cname})
	fake.deregisterMutex.Unlock()
	if fake.DeregisterStub != nil {
		return fake.DeregisterStub(cname)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.deregisterReturns.result1
}

func (fake *Registry) DeregisterCallCount() int {
	fake.deregisterMutex.RLock()
	defer fake.deregisterMutex.RUnlock()
	return len(fake.deregisterArgsForCall)
}

func (fake *Registry) DeregisterArgsForCall(i int) string {
	fake.deregisterMutex.RLock()
	defer fake.deregisterMutex.RUnlock()
	return fake.deregisterArgsForCall[i].cname
}

func (fake *Registry) DeregisterReturns(result1 error) {
	fake.DeregisterStub = nil
	fake.deregisterReturns = struct {
		result1 error
	}{result1}
}

func (fake *Registry) DeregisterReturnsOnCall(i int, result1 error) {
	fake.DeregisterStub = nil
	if fake.deregisterReturnsOnCall == nil {
		fake.deregisterReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.deregisterReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *Registry) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.registerMutex.RLock()
	defer fake.registerMutex.RUnlock()
	fake.readyMutex.RLock()
	defer fake.readyMutex.RUnlock()
	fake.failedMutex.RLock()
	defer fake.failedMutex.RUnlock()
	fake.deregisterMutex.RLock()
	defer fake.deregisterMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *Registry) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}
