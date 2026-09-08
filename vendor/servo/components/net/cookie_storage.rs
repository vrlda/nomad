/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! Implementation of cookie storage as specified in
//! <http://tools.ietf.org/html/rfc6265>

use std::cmp::Ordering;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::IpAddr;
use std::time::SystemTime;

use cookie::Cookie;
use itertools::Itertools;
use log::info;
use malloc_size_of_derive::MallocSizeOf;
use net_traits::pub_domains::reg_suffix;
use net_traits::{CookieSource, SiteDescriptor};
use serde::{Deserialize, Serialize};
use servo_url::ServoUrl;

use crate::cookie::ServoCookie;

#[derive(Clone, Debug, Deserialize, Serialize, MallocSizeOf)]
pub struct CookieStorage {
    version: u32,
    cookies_map: HashMap<String, Vec<ServoCookie>>,
    #[serde(default)]
    partitioned_cookies_map: HashMap<String, Vec<ServoCookie>>,
    max_per_host: usize,
}

#[derive(Debug)]
pub enum RemoveCookieError {
    Overlapping,
    NonHTTP,
}

impl CookieStorage {
    pub fn new(max_cookies: usize) -> CookieStorage {
        CookieStorage {
            version: 1,
            cookies_map: HashMap::new(),
            partitioned_cookies_map: HashMap::new(),
            max_per_host: max_cookies,
        }
    }

    // http://tools.ietf.org/html/rfc6265#section-5.3
    pub fn remove(
        &mut self,
        cookie: &ServoCookie,
        url: &ServoUrl,
        source: CookieSource,
    ) -> Result<Option<ServoCookie>, RemoveCookieError> {
        let domain = reg_host(cookie.cookie.domain().as_ref().unwrap_or(&""));
        remove_cookie_from_map(&mut self.cookies_map, &domain, cookie, url, source)
    }

    pub fn delete_cookies_for_sites(&mut self, sites: &Vec<String>) {
        // Note: We assume the number of sites is smaller than the number of
        // entries in the cookies map. If this assumption stops holding in
        // practice, this implementation can be revised to use `retain`
        // together with a temporary `HashSet` of sites.
        for site in sites {
            // TODO: We currently mark cookies as expired instead of removing
            // them immediately (same behavior as in the functions below).
            // This is safe because higher-level cookie accessors always call
            // `remove_expired_cookies_for_url` / `remove_all_expired_cookies`.
            // Consider whether we should instead delete the entries directly.
            if let Some(cookies) = self.cookies_map.get_mut(site) {
                for cookie in cookies.iter_mut() {
                    cookie.set_expiry_time_in_past();
                }
            }
        }
    }

    pub fn clear_session_cookies(&mut self) {
        self.cookies_map
            .values_mut()
            .flat_map(|cookies| cookies.iter_mut())
            .filter(|cookie| !cookie.persistent)
            .for_each(|cookie| cookie.set_expiry_time_in_past());
    }

    pub fn clear_storage(&mut self, url: Option<&ServoUrl>) {
        if let Some(url) = url {
            let domain = reg_host(url.host_str().unwrap_or(""));
            if let Some(cookies) = self.cookies_map.get_mut(&domain) {
                for cookie in cookies.iter_mut() {
                    cookie.set_expiry_time_in_past();
                }
            }
        } else {
            self.cookies_map.clear();
        }
    }

    pub fn delete_cookie_with_name(&mut self, url: &ServoUrl, name: String) {
        let domain = reg_host(url.host_str().unwrap_or(""));
        if let Some(cookies) = self.cookies_map.get_mut(&domain) {
            for cookie in cookies.iter_mut() {
                if cookie.cookie.name() == name {
                    cookie.set_expiry_time_in_past();
                }
            }
        }
    }

    pub fn delete_cookie_with_name_in_partition(
        &mut self,
        url: &ServoUrl,
        partition_url: &ServoUrl,
        name: String,
    ) {
        let key = partitioned_storage_key(partition_url, url);
        if let Some(cookies) = self.partitioned_cookies_map.get_mut(&key) {
            for cookie in cookies.iter_mut() {
                if cookie.cookie.name() == name {
                    cookie.set_expiry_time_in_past();
                }
            }
        }
    }

    // http://tools.ietf.org/html/rfc6265#section-5.3
    pub fn push(&mut self, cookie: ServoCookie, url: &ServoUrl, source: CookieSource) {
        let key = reg_host(cookie.cookie.domain().as_ref().unwrap_or(&""));
        push_cookie_into_map(
            &mut self.cookies_map,
            self.max_per_host,
            key,
            cookie,
            url,
            source,
        );
    }

    /// Stores a network cookie under the top-level site partition.
    pub fn push_in_partition(
        &mut self,
        cookie: ServoCookie,
        url: &ServoUrl,
        partition_url: &ServoUrl,
        source: CookieSource,
    ) {
        let key = partitioned_storage_key(partition_url, url);
        push_cookie_into_map(
            &mut self.partitioned_cookies_map,
            self.max_per_host,
            key,
            cookie,
            url,
            source,
        );
    }

    /// Removes expired network cookies from one top-level site partition.
    pub fn remove_expired_cookies_for_url_in_partition(
        &mut self,
        url: &ServoUrl,
        partition_url: &ServoUrl,
    ) {
        let key = partitioned_storage_key(partition_url, url);
        remove_expired_cookies_from_map(&mut self.partitioned_cookies_map, &key);
    }

    /// Returns network cookies visible to a request in one top-level site partition.
    pub fn cookies_for_url_in_partition(
        &mut self,
        url: &ServoUrl,
        partition_url: &ServoUrl,
        source: CookieSource,
    ) -> Option<String> {
        let cookie_list = self.cookies_data_for_url_in_partition(url, partition_url, source);
        let result = cookie_list
            .map(|cookie| format!("{}={}", cookie.name(), cookie.value()))
            .collect::<Vec<_>>()
            .join("; ");
        (!result.is_empty()).then_some(result)
    }

    pub fn cookies_data_for_url_in_partition<'a>(
        &'a mut self,
        url: &'a ServoUrl,
        partition_url: &'a ServoUrl,
        source: CookieSource,
    ) -> impl Iterator<Item = cookie::Cookie<'static>> + 'a {
        let key = partitioned_storage_key(partition_url, url);
        let cookies = self.partitioned_cookies_map.entry(key).or_default();
        cookies
            .iter_mut()
            .filter(move |cookie| cookie.appropriate_for_url(url, source))
            .sorted_by(|a: &&mut ServoCookie, b: &&mut ServoCookie| {
                CookieStorage::cookie_comparator(a, b)
            })
            .map(|cookie| {
                cookie.touch();
                cookie.cookie.clone()
            })
    }

    pub fn cookie_comparator(a: &ServoCookie, b: &ServoCookie) -> Ordering {
        let a_path_len = a.cookie.path().as_ref().map_or(0, |p| p.len());
        let b_path_len = b.cookie.path().as_ref().map_or(0, |p| p.len());
        match a_path_len.cmp(&b_path_len) {
            Ordering::Equal => a.creation_time.cmp(&b.creation_time),
            // Ensure that longer paths are sorted earlier than shorter paths
            Ordering::Greater => Ordering::Less,
            Ordering::Less => Ordering::Greater,
        }
    }

    pub fn remove_expired_cookies_for_url(&mut self, url: &ServoUrl) {
        let domain = reg_host(url.host_str().unwrap_or(""));
        if let Entry::Occupied(mut entry) = self.cookies_map.entry(domain) {
            let cookies = entry.get_mut();
            cookies.retain(|c| !is_cookie_expired(c));
            if cookies.is_empty() {
                entry.remove_entry();
            }
        }
    }

    pub fn remove_all_expired_cookies(&mut self) {
        self.cookies_map.retain(|_, cookies| {
            cookies.retain(|c| !is_cookie_expired(c));
            !cookies.is_empty()
        });
    }

    // http://tools.ietf.org/html/rfc6265#section-5.4
    pub fn cookies_for_url(&mut self, url: &ServoUrl, source: CookieSource) -> Option<String> {
        // Let cookie-list be the set of cookies from the cookie store
        let cookie_list = self.cookies_data_for_url(url, source);

        let reducer = |acc: String, cookie: Cookie<'static>| -> String {
            // Serialize the cookie-list into a cookie-string by processing each cookie in the cookie-list in order:
            // If the cookies' name is not empty, output the cookie's name followed by the %x3D ("=") character.
            // If the cookies' value is not empty, output the cookie's value.
            // If there is an unprocessed cookie in the cookie-list, output the characters %x3B and %x20 ("; ").
            // Security: the above steps allow for "nameless" cookies which have proved to be a security footgun
            // especially with the new cookie name prefix proposals
            (match acc.len() {
                0 => acc,
                _ => acc + "; ",
            }) + cookie.name()
                + "="
                + cookie.value()
        };

        // Serialize the cookie-list into a cookie-string by processing each cookie in the cookie-list in order
        let result = cookie_list.fold("".to_owned(), reducer);

        info!(" === COOKIES SENT: {}", result);
        match result.len() {
            0 => None,
            _ => Some(result),
        }
    }

    /// <https://cookiestore.spec.whatwg.org/#query-cookies>
    pub fn query_cookies(&mut self, url: &ServoUrl, name: Option<String>) -> Vec<Cookie<'static>> {
        // 1. Retrieve cookie-list given request-uri and "non-HTTP" source
        let cookie_list = self.cookies_data_for_url(url, CookieSource::NonHTTP);

        // 3. For each cookie in cookie-list, run these steps:
        // 3.2. If name is given, then run these steps:
        if let Some(name) = name {
            // Let cookieName be the result of running UTF-8 decode without BOM on cookie’s name.
            // If cookieName does not equal name, then continue.
            cookie_list.filter(|cookie| cookie.name() == name).collect()
        } else {
            cookie_list.collect()
        }

        // Note: we do not convert the list into CookieListItem's here, we do that in script to not not have to define
        // the binding types in net.

        // Return list
    }

    pub fn cookies_data_for_url<'a>(
        &'a mut self,
        url: &'a ServoUrl,
        source: CookieSource,
    ) -> impl Iterator<Item = cookie::Cookie<'static>> + 'a {
        let domain = reg_host(url.host_str().unwrap_or(""));
        let cookies = self.cookies_map.entry(domain).or_default();

        cookies
            .iter_mut()
            .filter(move |c| c.appropriate_for_url(url, source))
            .sorted_by(|a: &&mut ServoCookie, b: &&mut ServoCookie| {
                // The user agent SHOULD sort the cookie-list
                CookieStorage::cookie_comparator(a, b)
            })
            .map(|c| {
                // Update the last-access-time of each cookie in the cookie-list to the current date and time
                c.touch();
                c.cookie.clone()
            })
    }

    pub fn cookie_site_descriptors(&self) -> Vec<SiteDescriptor> {
        self.cookies_map
            .keys()
            .cloned()
            .map(SiteDescriptor::new)
            .collect()
    }
}

fn reg_host(url: &str) -> String {
    let host_for_ip_parse = url
        .strip_prefix('[')
        .and_then(|url| url.strip_suffix(']'))
        .unwrap_or(url);
    if let Ok(address) = host_for_ip_parse.parse::<IpAddr>() {
        return address.to_string().to_lowercase();
    }

    reg_suffix(url).to_lowercase()
}

fn partitioned_storage_key(partition_url: &ServoUrl, cookie_url: &ServoUrl) -> String {
    let partition = partition_url
        .host_str()
        .map(reg_host)
        .filter(|site| !site.is_empty())
        .unwrap_or_else(|| partition_url.as_str().to_lowercase());
    format!(
        "{partition}\u{1f}{}",
        reg_host(cookie_url.host_str().unwrap_or(""))
    )
}

fn remove_cookie_from_map(
    cookies_map: &mut HashMap<String, Vec<ServoCookie>>,
    key: &str,
    cookie: &ServoCookie,
    url: &ServoUrl,
    source: CookieSource,
) -> Result<Option<ServoCookie>, RemoveCookieError> {
    let cookies = cookies_map.entry(key.to_owned()).or_default();

    if !cookie.cookie.secure().unwrap_or(false) && !url.is_secure_scheme() {
        let new_domain = cookie.cookie.domain().unwrap().to_owned();
        let new_path = cookie.cookie.path().unwrap().to_owned();

        let any_overlapping = cookies.iter().any(|existing| {
            let existing_domain = existing.cookie.domain().unwrap().to_owned();
            let existing_path = existing.cookie.path().unwrap().to_owned();

            existing.cookie.name() == cookie.cookie.name()
                && existing.cookie.secure().unwrap_or(false)
                && (ServoCookie::domain_match(&new_domain, &existing_domain)
                    || ServoCookie::domain_match(&existing_domain, &new_domain))
                && ServoCookie::path_match(&new_path, &existing_path)
        });

        if any_overlapping {
            return Err(RemoveCookieError::Overlapping);
        }
    }

    let position = cookies.iter().position(|existing| {
        existing.cookie.domain() == cookie.cookie.domain()
            && existing.cookie.path() == cookie.cookie.path()
            && existing.cookie.name() == cookie.cookie.name()
    });

    let Some(index) = position else {
        return Ok(None);
    };
    let existing = cookies.remove(index);
    if existing.cookie.http_only().unwrap_or(false) && source == CookieSource::NonHTTP {
        cookies.push(existing);
        Err(RemoveCookieError::NonHTTP)
    } else {
        Ok(Some(existing))
    }
}

fn push_cookie_into_map(
    cookies_map: &mut HashMap<String, Vec<ServoCookie>>,
    max_per_host: usize,
    key: String,
    mut cookie: ServoCookie,
    url: &ServoUrl,
    source: CookieSource,
) {
    if cookie.cookie.secure().unwrap_or(false) && !url.is_secure_scheme() {
        return;
    }

    let old_cookie = remove_cookie_from_map(cookies_map, &key, &cookie, url, source);
    if old_cookie.is_err() {
        return;
    }
    if let Some(old_cookie) = old_cookie.unwrap() {
        cookie.creation_time = old_cookie.creation_time;
    }

    let cookies = cookies_map.entry(key).or_default();
    if cookies.len() == max_per_host {
        let old_len = cookies.len();
        cookies.retain(|existing| !is_cookie_expired(existing));
        if cookies.len() == old_len
            && !evict_one_cookie(cookie.cookie.secure().unwrap_or(false), cookies)
        {
            return;
        }
    }
    cookies.push(cookie);
}

fn remove_expired_cookies_from_map(cookies_map: &mut HashMap<String, Vec<ServoCookie>>, key: &str) {
    if let Entry::Occupied(mut entry) = cookies_map.entry(key.to_owned()) {
        let cookies = entry.get_mut();
        cookies.retain(|cookie| !is_cookie_expired(cookie));
        if cookies.is_empty() {
            entry.remove_entry();
        }
    }
}

fn is_cookie_expired(cookie: &ServoCookie) -> bool {
    matches!(cookie.expiry_time, Some(date_time) if date_time <= SystemTime::now())
}

fn evict_one_cookie(is_secure_cookie: bool, cookies: &mut Vec<ServoCookie>) -> bool {
    // Remove non-secure cookie with oldest access time
    let oldest_accessed = get_oldest_accessed(false, cookies);

    if let Some((index, _)) = oldest_accessed {
        cookies.remove(index);
    } else {
        // All secure cookies were found
        if !is_secure_cookie {
            return false;
        }
        let oldest_accessed = get_oldest_accessed(true, cookies);
        if let Some((index, _)) = oldest_accessed {
            cookies.remove(index);
        }
    }
    true
}

fn get_oldest_accessed(
    is_secure_cookie: bool,
    cookies: &mut [ServoCookie],
) -> Option<(usize, SystemTime)> {
    let mut oldest_accessed = None;
    for (i, c) in cookies.iter().enumerate() {
        if (c.cookie.secure().unwrap_or(false) == is_secure_cookie)
            && oldest_accessed
                .as_ref()
                .is_none_or(|(_, current_oldest_time)| c.last_access < *current_oldest_time)
        {
            oldest_accessed = Some((i, c.last_access));
        }
    }
    oldest_accessed
}
