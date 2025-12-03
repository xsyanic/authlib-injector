/*
 * Copyright (C) 2020  Haowei Wen <yushijinhun@gmail.com> and contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package moe.yushi.authlibinjector.httpd;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import moe.yushi.authlibinjector.APIMetadata;

public class DefaultURLRedirector implements URLRedirector {

	private Map<String, String> domainMapping = new HashMap<>();
	private String apiRoot;

	public DefaultURLRedirector(APIMetadata config) {
		initDomainMapping();

		apiRoot = config.getApiRoot();
	}

	private void initDomainMapping() {
		domainMapping.put("api.mojang.com", "api");
		domainMapping.put("sessionserver.mojang.com", "sessionserver");
		domainMapping.put("skins.minecraft.net", "skins");
		domainMapping.put("api.minecraftservices.com", "minecraftservices");
	}

	@Override
	public Optional<String> redirect(String domain, String path) {
		String subdirectory = domainMapping.get(domain);
		if (subdirectory == null) {
			return Optional.empty();
		}

		// For sessionserver, only proxy the profile endpoint
		if ("sessionserver".equals(subdirectory)) {
			if (isProfileEndpoint(path)) {
				return Optional.of(apiRoot + subdirectory + path);
			}
			// Other sessionserver endpoints (join, hasJoined) are not redirected
			return Optional.empty();
		}

		return Optional.of(apiRoot + subdirectory + path);
	}

	private boolean isProfileEndpoint(String path) {
		// Match /session/minecraft/profile/{uuid} and /session/minecraft/profile/{uuid}?...
		// UUIDs are 32 hex digits (case-insensitive) with optional hyphens
		return path.matches("/session/minecraft/profile/[a-fA-F0-9\\-]+.*");
	}

}
