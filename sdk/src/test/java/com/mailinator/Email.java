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
package com.mailinator;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

/**
 *
 * @author Adam Boulton
 */
public class Email {

	// private int apiInboxFetchesLeft;
	private int apiEmailFetchesLeft;
	// private int forwardsLeft;

	// Represents the data section in the JSON feed
	private long secondsAgo;
	private String id;
	private String to;
	private long time;
	private String subject;
	private String fromFull;

	// Represents the headers in the data section on the root of a message JSON
	// feed
	private HashMap<String, String> headers;

	// Represents the parts section of the email JSON feed
	private Set<EmailPart> emailParts = new HashSet<>();

	public int getApiEmailFetchesLeft() {
		return apiEmailFetchesLeft;
	}

	protected void setApiEmailFetchesLeft(int apiEmailFetchesLeft) {
		this.apiEmailFetchesLeft = apiEmailFetchesLeft;
	}

	public long getSecondsAgo() {
		return secondsAgo;
	}

	protected void setSecondsAgo(long secondsAgo) {
		this.secondsAgo = secondsAgo;
	}

	public String getId() {
		return id;
	}

	protected void setId(String id) {
		this.id = id;
	}

	public String getTo() {
		return to;
	}

	protected void setTo(String to) {
		this.to = to;
	}

	public long getTime() {
		return time;
	}

	protected void setTime(long time) {
		this.time = time;
	}

	public String getSubject() {
		return subject;
	}

	protected void setSubject(String subject) {
		this.subject = subject;
	}

	public String getFromFull() {
		return fromFull;
	}

	protected void setFromFull(String fromFull) {
		this.fromFull = fromFull;
	}

	public HashMap<String, String> getHeaders() {
		return headers;
	}

	protected void setHeaders(HashMap<String, String> headers) {
		this.headers = headers;
	}

	public Set<EmailPart> getEmailParts() {
		return emailParts;
	}

	protected void setEmailParts(Set<EmailPart> emailParts) {
		this.emailParts = emailParts;
	}

	public class EmailPart {

		private HashMap<String, String> headers;
		private String body;

		public HashMap<String, String> getHeaders() {
			return headers;
		}

		protected void setHeaders(HashMap<String, String> headers) {
			this.headers = headers;
		}

		public String getBody() {
			return body;
		}

		protected void setBody(String body) {
			this.body = body;
		}

	}

	@Override
	public String toString() {
		return "Email{" + "apiEmailFetchesLeft=" + apiEmailFetchesLeft + ", secondsAgo=" + secondsAgo + ", id=" + id
				+ ", to=" + to + ", time=" + time + ", subject=" + subject + ", fromFull=" + fromFull + ", headers="
				+ headers + ", emailParts=" + emailParts + '}';
	}

}