/* Copyright 2019 New Vector Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package gomatrixserverlib

// A Version is a struct that matches the version response from a Matrix homeserver. See
// https://matrix.org/docs/spec/server_server/r0.1.1.html#get-matrix-federation-v1-version
type Version struct {
	// Server is a struct containing the homserver version values
	Server struct {
		// Name is an arbitrary string that the Matrix server uses to identify itself
		Name string `json:"name"`
		// Version is a string that identifies the Matrix server's version, the format
		// of which depends on the Matrx server implementation
		Version string `json:"version"`
	} `json:"server"`
}
