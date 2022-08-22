'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');

class MyWorkload extends WorkloadModuleBase {
    constructor() {
        super();
    }

    async submitTransaction() {
        const myArgs = {
            contractId: this.roundArguments.contractId,
            contractFunction: 'QueryToken',
            invokerIdentity: 'User1',
            contractArguments: ["ec2-3-64-124-240.eu-central-1.compute.amazonaws.com"],
            readOnly: true
        };

        await this.sutAdapter.sendRequests(myArgs);
    }
    async cleanupWorkloadModule() {
        // NOOP
    }

}

function createWorkloadModule() {
    return new MyWorkload();
}

module.exports.createWorkloadModule = createWorkloadModule;