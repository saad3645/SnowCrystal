/*
 * Copyright (c) 2013 Saad Ahmed
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.saadahmed.snowcrystal;

/**
 *
 * @author Saad Ahmed
 */
public class ClockMovedBackException extends RuntimeException {

	public ClockMovedBackException() {
		super();
	}

	public ClockMovedBackException(String message) {
		super(message);
	}

	public ClockMovedBackException(Throwable cause) {
		super(cause);
	}

	public ClockMovedBackException(String message, Throwable cause) {
		super(message, cause);
	}

}
