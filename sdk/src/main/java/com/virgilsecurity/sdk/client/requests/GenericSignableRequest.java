/*******************************************************************************
 * Copyright (c) 2015-2018, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
package com.virgilsecurity.sdk.client.requests;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.virgilsecurity.sdk.client.model.dto.SignableRequestMetaModel;
import com.virgilsecurity.sdk.client.model.dto.SignableRequestModel;
import com.virgilsecurity.sdk.client.model.dto.SignableRequestValidationModel;
import com.virgilsecurity.sdk.exception.EmptyArgumentException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;

/**
 * Base class for requests.
 *
 * @author Andrii Iakovenko
 *
 */
public abstract class GenericSignableRequest<T> implements SignableRequest {

    protected Type type;
    protected Map<String, byte[]> acceptedSignatures;
    protected byte[] takenSnapshot;
    protected T snapshotModel;
    protected String validationToken;

    /**
     * Create a new instance of {@code SignedRequest}
     *
     */
    GenericSignableRequest() {
        if (getClass().getGenericSuperclass() instanceof ParameterizedType) {
            this.type = ((ParameterizedType) getClass().getGenericSuperclass()).getActualTypeArguments()[0];
        }
        this.acceptedSignatures = new HashMap<>();
    }

    /**
     * Create new instance of {@link GenericSignableRequest}.
     * 
     * @param stringifiedRequest
     *            The request as a string.
     */
    GenericSignableRequest(String stringifiedRequest) {
        this();
        importRequest(stringifiedRequest);
    }

    /**
     * Initialize request with snapshot.
     * 
     * @param snapshotModel
     *            The model of snapshot.
     */
    protected void init(T snapshotModel) {
        this.snapshotModel = snapshotModel;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.client.requests.SignableRequest#getSnapshot()
     */
    public byte[] getSnapshot() {
        if (this.takenSnapshot == null) {
            this.takenSnapshot = takeSnapshot();
        }
        return this.takenSnapshot;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.client.requests.SignableRequest#getSignatures()
     */
    public Map<String, byte[]> getSignatures() {
        return Collections.unmodifiableMap(this.acceptedSignatures);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.client.requests.SignableRequest#appendSignature(java.lang.String, byte[])
     */
    @Override
    public void appendSignature(String cardId, byte[] signature) {
        if (StringUtils.isBlank(cardId)) {
            throw new EmptyArgumentException("cardId");
        }

        if (signature == null) {
            throw new NullArgumentException("signature");
        }

        this.acceptedSignatures.put(cardId, signature);
    }

    /**
     * Gets the request model.
     * 
     * @return The request model.
     */
    public SignableRequestModel getRequestModel() {
        SignableRequestModel requestModel = new SignableRequestModel();
        requestModel.setContentSnapshot(this.getSnapshot());

        SignableRequestMetaModel meta = new SignableRequestMetaModel();
        meta.setSignatures(this.getSignatures());
        requestModel.setMeta(meta);

        if (!StringUtils.isBlank(this.validationToken)) {
            requestModel.getMeta().setValidation(new SignableRequestValidationModel(this.validationToken));
        }

        return requestModel;
    }

    /**
     * Extracts the request snapshot model from actual snapshotModel.
     * 
     * @return The extracted snapshot model.
     */
    public T extractSnapshotModel() {
        String jsonSnapshot = ConvertionUtils.toString(this.getSnapshot());
        return ConvertionUtils.getGson().fromJson(jsonSnapshot, type);
    }

    /**
     * Export request.
     * 
     * @return the request model as string.
     */
    public String exportRequest() {
        SignableRequestModel requestModel = this.getRequestModel();

        String json = ConvertionUtils.getGson().toJson(requestModel);
        return ConvertionUtils.toBase64String(json);
    }

    /**
     * Import request.
     * 
     * @param exportedRequest
     *            The request as Base64 encoded string.
     */
    protected void importRequest(String exportedRequest) {
        String jsonModel = ConvertionUtils.base64ToString(exportedRequest);
        SignableRequestModel requestModel = ConvertionUtils.getGson().fromJson(jsonModel, SignableRequestModel.class);

        this.takenSnapshot = requestModel.getContentSnapshot();

        if (requestModel.getMeta() != null) {
            this.acceptedSignatures = new HashMap<>(requestModel.getMeta().getSignatures());

            if (requestModel.getMeta().getValidation() != null) {
                this.validationToken = requestModel.getMeta().getValidation().getToken();
            }
        }
    }

    /**
     * Takes the request snapshot.
     * 
     * @return the snapshot.
     */
    protected byte[] takeSnapshot() {
        if (this.takenSnapshot != null) {
            return this.takenSnapshot;
        }

        this.takenSnapshot = ConvertionUtils.captureSnapshot(this.snapshotModel);
        return this.takenSnapshot;
    }

}
