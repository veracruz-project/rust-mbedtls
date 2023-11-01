/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#[cfg(feature = "debug")]
pub const DEFAULT_MBEDTLS_DEBUG_LEVEL: i32 = 3;

pub fn init_env_logger() {
    let _ = env_logger::builder().is_test(true).try_init();
}
