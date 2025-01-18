/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 OSSLSM4.cpp

 OpenSSL SM4 implementation
 *****************************************************************************/

#include "config.h"
#include "OSSLSM4.h"
#include <algorithm>
#include "salloc.h"

// Wrap/Unwrap keys
bool OSSLSM4::wrapKey(const SymmetricKey* key, const SymWrap::Type mode, const ByteString& in, ByteString& out)
{
	ERROR_MSG("SM4 does not support key wrapping");

	return false;
}

bool OSSLSM4::unwrapKey(const SymmetricKey* key, const SymWrap::Type mode, const ByteString& in, ByteString& out)
{
	ERROR_MSG("SM4 does not support key unwrapping");

	return false;
}

const EVP_CIPHER* OSSLSM4::getCipher() const
{
	if (currentKey == NULL) return NULL;

	// Check currentKey bit length; SM4 only supports 128 bit keys
	if (currentKey->getBitLen() != 128)
	{
		ERROR_MSG("Invalid SM4 currentKey length (%d bits)", currentKey->getBitLen());

		return NULL;
	}

	// Determine the cipher mode
    switch(currentCipherMode)
    {
        case SymMode::CBC:
            return EVP_sm4_cbc();
        case SymMode::ECB:
            return EVP_sm4_ecb();
        case SymMode::CTR:
            return EVP_sm4_ctr();
    };

	ERROR_MSG("Invalid SM4 cipher mode %i", currentCipherMode);

	return NULL;
}

size_t OSSLSM4::getBlockSize() const
{
	// The block size is 128 bits
	return 128 >> 3;
}
