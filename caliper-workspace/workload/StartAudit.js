'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');

class MyWorkload extends WorkloadModuleBase {
    constructor() {
        super();
    }

    async submitTransaction() {
        const myArgs = {
            contractId: this.roundArguments.contractId,
            contractFunction: 'StartAudit',
            invokerIdentity: 'User1',
            contractArguments: ["ec2-3-64-124-240.eu-central-1.compute.amazonaws.com", "ubuntu", "xxxxxx"],
            readOnly: false,
            timeout: 120
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