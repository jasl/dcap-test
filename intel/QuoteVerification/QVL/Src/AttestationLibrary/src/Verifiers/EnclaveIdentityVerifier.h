/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef SGXECDSAATTESTATION_ENCLAVEIDENTITYVERIFIER_H
#define SGXECDSAATTESTATION_ENCLAVEIDENTITYVERIFIER_H

#include "CommonVerifier.h"
#include "TCBSigningChain.h"
#include "EnclaveIdentityV2.h"
#include <SgxEcdsaAttestation/QuoteVerification.h>
#include <CertVerification/CertificateChain.h>
#include <PckParser/CrlStore.h>

namespace intel { namespace sgx { namespace dcap {

class EnclaveIdentityVerifier
{
public:
    EnclaveIdentityVerifier();
    EnclaveIdentityVerifier(std::unique_ptr<CommonVerifier>&& commonVerifier,
    std::unique_ptr<TCBSigningChain>&& tcbSigningChain);
    EnclaveIdentityVerifier(const EnclaveIdentityVerifier&) = delete;
    EnclaveIdentityVerifier(EnclaveIdentityVerifier&&) = delete;
    EnclaveIdentityVerifier& operator=(const EnclaveIdentityVerifier&) = delete;
    EnclaveIdentityVerifier& operator=(EnclaveIdentityVerifier&&) = delete;
    ~EnclaveIdentityVerifier() = default;


    /**
     * Verify corectness of enclave identity certificate and Json
     * Checks subject, issuer, validity period, extensions and signature.
     *
     * @param enclaveIdentity - enclave identity to verify
     * @param chain - enclave identity chain verify
     * @param rootCaCrl - root CRL
     * @param trustedRoot - trusted root certificate
     * @return Status code of the operation
     */
    Status verify(
            const EnclaveIdentityV2 &enclaveIdentity,
            const CertificateChain &chain,
            const pckparser::CrlStore &rootCaCrl,
            const dcap::parser::x509::Certificate &trustedRoot,
            const std::time_t& expirationDate) const;

private:
    std::unique_ptr<CommonVerifier> _commonVerifier;
    std::unique_ptr<TCBSigningChain> _tcbSigningChain;
};

}}} // namespace intel { namespace sgx { namespace dcap {

#endif //SGXECDSAATTESTATION_ENCLAVEIDENTITYVERIFIER_H
