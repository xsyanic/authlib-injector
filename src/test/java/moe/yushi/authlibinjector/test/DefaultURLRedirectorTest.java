/*
 * Copyright (C) 2022  Haowei Wen <yushijinhun@gmail.com> and contributors
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
package moe.yushi.authlibinjector.test;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static org.junit.jupiter.api.Assertions.assertEquals;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import moe.yushi.authlibinjector.APIMetadata;
import moe.yushi.authlibinjector.httpd.DefaultURLRedirector;

public class DefaultURLRedirectorTest {

	private String apiRoot = "https://yggdrasil.example.com/";
	private DefaultURLRedirector redirector = new DefaultURLRedirector(new APIMetadata(apiRoot, emptyList(), emptyMap(), Optional.empty()));

	private void testTransform(String domain, String path, String output) {
		assertEquals(redirector.redirect(domain, path).get(), output);
	}

	@Test
	public void testReplace() {
		testTransform(
				// from: [com.mojang:authlib:1.5.24]/com.mojang.authlib.yggdrasil.YggdrasilGameProfileRepository
				"api.mojang.com", "/profiles/",
				"https://yggdrasil.example.com/api/profiles/");

		// SessionServer /join endpoint should NOT be redirected
		assertEquals(redirector.redirect("sessionserver.mojang.com", "/session/minecraft/join"), Optional.empty());

		// SessionServer /hasJoined endpoint should NOT be redirected
		assertEquals(redirector.redirect("sessionserver.mojang.com", "/session/minecraft/hasJoined"), Optional.empty());

		testTransform(
				// from: [mcp940]/net.minecraft.client.entity.AbstractClientPlayer
				// issue: yushijinhun/authlib-injector#7 <https://github.com/yushijinhun/authlib-injector/issues/7>
				"skins.minecraft.net", "/MinecraftSkins/%s.png",
				"https://yggdrasil.example.com/skins/MinecraftSkins/%s.png");

		// SessionServer /hasJoined with query parameter should also NOT be redirected
		assertEquals(redirector.redirect("sessionserver.mojang.com", "/session/minecraft/hasJoined?username="), Optional.empty());

		testTransform(
				// from: [wiki.vg]/Mojang_API/Username -> UUID at time
				// url: http://wiki.vg/Mojang_API#Username_-.3E_UUID_at_time
				// issue: yushijinhun/authlib-injector#6 <https://github.com/yushijinhun/authlib-injector/issues/6>
				"api.mojang.com", "/users/profiles/minecraft/",
				"https://yggdrasil.example.com/api/users/profiles/minecraft/");

		// SessionServer /profile endpoint should be redirected
		testTransform(
				"sessionserver.mojang.com", "/session/minecraft/profile/12345678abcdef0012345678abcdef00",
				"https://yggdrasil.example.com/sessionserver/session/minecraft/profile/12345678abcdef0012345678abcdef00");

		// SessionServer /profile with query parameter should also be redirected
		testTransform(
				"sessionserver.mojang.com", "/session/minecraft/profile/12345678abcdef0012345678abcdef00?unsigned=false",
				"https://yggdrasil.example.com/sessionserver/session/minecraft/profile/12345678abcdef0012345678abcdef00?unsigned=false");
	}

	@Test
	public void testEmpty() {
		assertEquals(redirector.redirect("example.com", "/path"), Optional.empty());
	}

}
