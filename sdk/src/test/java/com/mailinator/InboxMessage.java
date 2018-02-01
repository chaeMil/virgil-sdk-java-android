/*
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
 */

package com.mailinator;

/**
 *
 * @author Adam Boulton
 */
public class InboxMessage {
	private long secondsAgo;
	private String to;
	private String id;
	private long time;
	private String subject;
	private String fromFull;
	private boolean beenRead;
	private String from;
	private String ip;

	// Auto generated getter / setters
	public long getSeconds_ago() {
		return secondsAgo;
	}

	protected void setSeconds_ago(long seconds_ago) {
		this.secondsAgo = seconds_ago;
	}

	public String getId() {
		return id;
	}

	protected void setId(String id) {
		this.id = id;
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

	public String getFromfull() {
		return fromFull;
	}

	protected void setFromfull(String fromfull) {
		this.fromFull = fromfull;
	}

	public boolean isBeen_read() {
		return beenRead;
	}

	protected void setBeen_read(boolean been_read) {
		this.beenRead = been_read;
	}

	public String getFrom() {
		return from;
	}

	protected void setFrom(String from) {
		this.from = from;
	}

	public String getIp() {
		return ip;
	}

	protected void setIp(String ip) {
		this.ip = ip;
	}

	public String getTo() {
		return to;
	}

	protected void setTo(String to) {
		this.to = to;
	}

	@Override
	public String toString() {
		return "InboxMessage{" + "secondsAgo=" + secondsAgo + ", to=" + to + ", id=" + id + ", time=" + time
				+ ", subject=" + subject + ", fromFull=" + fromFull + ", beenRead=" + beenRead + ", from=" + from
				+ ", ip=" + ip + '}';
	}

}