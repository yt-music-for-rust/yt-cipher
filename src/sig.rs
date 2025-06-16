use const_format::{concatcp, formatcp};
use fancy_regex::Regex as FancyRegex;
use regex::{Regex, RegexSet};

pub type Result<T> = std::result::Result<T, &'static str>;

pub const VARIABLE_PART: &str = "[a-zA-Z_\\$][a-zA-Z_0-9\\$]*";
pub const VARIABLE_PART_DEFINE: &str = concatcp!("\\\"?", VARIABLE_PART, "\\\"?");
pub const BEFORE_ACCESS: &str = "(?:\\[\\\"|\\.)";
pub const AFTER_ACCESS: &str = "(?:\\\"\\]|)";
pub const VARIABLE_PART_ACCESS: &str = concatcp!(BEFORE_ACCESS, VARIABLE_PART, AFTER_ACCESS);
pub const REVERSE_PART: &str = ":function\\(\\w\\)\\{(?:return )?\\w\\.reverse\\(\\)\\}";
pub const SLICE_PART: &str = ":function\\(\\w,\\w\\)\\{return \\w\\.slice\\(\\w\\)\\}";
pub const SPLICE_PART: &str = ":function\\(\\w,\\w\\)\\{\\w\\.splice\\(0,\\w\\)\\}";
pub const SWAP_PART: &str = concat!(
    ":function\\(\\w,\\w\\)\\{",
    "var \\w=\\w\\[0\\];\\w\\[0\\]=\\w\\[\\w%\\w\\.length\\];\\w\\[\\w(?:%\\w\\.length|)\\]=\\w(?:;return \\w)?\\}",
);

pub const DECIPHER_REGEXP: &str = concatcp!(
    "function(?: ",
    VARIABLE_PART,
    ")?\\(([a-zA-Z])\\)\\{",
    "\\1=\\1\\.split\\(\"\"\\);\\s*",
    "((?:(?:\\1=)?",
    VARIABLE_PART,
    VARIABLE_PART_ACCESS,
    "\\(\\1,\\d+\\);)+)",
    "return \\1\\.join\\(\"\"\\)",
    "\\}",
);

pub const HELPER_REGEXP: &str = concatcp!(
    "var (",
    VARIABLE_PART,
    ")=\\{((?:(?:",
    VARIABLE_PART_DEFINE,
    REVERSE_PART,
    "|",
    VARIABLE_PART_DEFINE,
    SLICE_PART,
    "|",
    VARIABLE_PART_DEFINE,
    SPLICE_PART,
    "|",
    VARIABLE_PART_DEFINE,
    SWAP_PART,
    "),?\\n?)+)\\};",
);

pub const FUNCTION_TCE_REGEXP: &str = concat!(
    "function(?:\\s+[a-zA-Z_\\$][a-zA-Z0-9_\\$]*)?\\(\\w\\)\\{",
    "\\w=\\w\\.split\\((?:\"\"|[a-zA-Z0-9_$]*\\[\\d+])\\);",
    "\\s*((?:(?:\\w=)?[a-zA-Z_\\$][a-zA-Z0-9_\\$]*(?:\\[\\\"|\\.)[a-zA-Z_\\$][a-zA-Z0-9_\\$]*(?:\\\"\\]|)\\(\\w,\\d+\\);)+)",
    "return \\w\\.join\\((?:\"\"|[a-zA-Z0-9_$]*\\[\\d+])\\)}",
);

pub const N_TRANSFORM_REGEXP: &str = concat!(
    "function\\(\\s*(\\w+)\\s*\\)\\s*\\{",
    "var\\s*(\\w+)=(?:\\1\\.split\\(.*?\\)|String\\.prototype\\.split\\.call\\(\\1,.*?\\)),",
    "\\s*(\\w+)=(\\[.*?]);\\s*\\3\\[\\d+]",
    "(.*?try)(\\{.*?})catch\\(\\s*(\\w+)\\s*\\)\\s*\\{",
    "\\s*return\"[\\w-]+([A-z0-9-]+)\"\\s*\\+\\s*\\1\\s*}",
    "\\s*return\\s*(\\2\\.join\\(\"\"\\)|Array\\.prototype\\.join\\.call\\(\\2,.*?\\))};",
);

pub const N_TRANSFORM_TCE_REGEXP: &str = concat!(
    "function\\(\\s*(\\w+)\\s*\\)\\s*\\{",
    "\\s*var\\s*(\\w+)=\\1\\.split\\(\\1\\.slice\\(0,0\\)\\),\\s*(\\w+)=\\[.*?];",
    ".*?catch\\(\\s*(\\w+)\\s*\\)\\s*\\{",
    "\\s*return(?:\"[^\"]+\"|\\s*[a-zA-Z_0-9$]*\\[\\d+])\\s*\\+\\s*\\1\\s*}",
    "\\s*return\\s*\\2\\.join\\((?:\"\"|[a-zA-Z_0-9$]*\\[\\d+])\\)};",
);

pub const TCE_GLOBAL_VARS_REGEXP: &str = concat!(
    "(?:^|[;,])\\s*(var\\s+([\\w$]+)\\s*=\\s*",
    "(?:",
    "([\"'])(?:\\\\.|[^\\\\])*?\\3",
    "\\s*\\.\\s*split\\((",
    "([\"'])(?:\\\\.|[^\\\\])*?\\5",
    "\\))",
    "|",
    "\\[\\s*(?:([\"'])(?:\\\\.|[^\\\\])*?\\6\\s*,?\\s*)+\\]",
    "))(?=\\s*[,;])",
);

pub const NEW_TCE_GLOBAL_VARS_REGEXP: &str = concat!(
    "('use\\s*strict';)?",
    "(?<code>var\\s*",
    "(?<varname>[a-zA-Z0-9_$]+)\\s*=\\s*",
    "(?<value>",
    "(?:\"[^\"\\\\]*(?:\\\\.[^\"\\\\]*)*\"|'[^'\\\\]*(?:\\\\.[^'\\\\]*)*')",
    "\\.split\\(",
    "(?:\"[^\"\\\\]*(?:\\\\.[^\"\\\\]*)*\"|'[^'\\\\]*(?:\\\\.[^'\\\\]*)*')",
    "\\)",
    "|",
    "\\[",
    "(?:(?:\"[^\"\\\\]*(?:\\\\.[^\"\\\\]*)*\"|'[^'\\\\]*(?:\\\\.[^'\\\\]*)*')",
    "\\s*,?\\s*)*",
    "\\]",
    "|",
    "\"[^\"]*\"\\.split\\(\"[^\"]*\"\\)",
    ")",
    ")",
);

pub const TCE_SIGN_FUNCTION_REGEXP: &str = concat!(
    "function\\(\\s*([a-zA-Z0-9$])\\s*\\)\\s*\\{",
    "\\s*\\1\\s*=\\s*\\1\\[(\\w+)\\[\\d+\\]\\]\\(\\2\\[\\d+\\]\\);",
    "([a-zA-Z0-9$]+)\\[\\2\\[\\d+\\]\\]\\(\\s*\\1\\s*,\\s*\\d+\\s*\\);",
    "\\s*\\3\\[\\2\\[\\d+\\]\\]\\(\\s*\\1\\s*,\\s*\\d+\\s*\\);",
    ".*?return\\s*\\1\\[\\2\\[\\d+\\]\\]\\(\\2\\[\\d+\\]\\)\\};",
);

pub const TCE_SIGN_FUNCTION_ACTION_REGEXP: &str = "var\\s+([$A-Za-z0-9_]+)\\s*=\\s*\\{\\s*[$A-Za-z0-9_]+\\s*:\\s*function\\s*\\([^)]*\\)\\s*\\{[^{}]*(?:\\{[^{}]*}[^{}]*)*}\\s*,\\s*[$A-Za-z0-9_]+\\s*:\\s*function\\s*\\([^)]*\\)\\s*\\{[^{}]*(?:\\{[^{}]*}[^{}]*)*}\\s*,\\s*[$A-Za-z0-9_]+\\s*:\\s*function\\s*\\([^)]*\\)\\s*\\{[^{}]*(?:\\{[^{}]*}[^{}]*)*}\\s*};";

pub const TCE_N_FUNCTION_REGEXP: &str = "function\\s*\\((\\w+)\\)\\s*\\{var\\s*\\w+\\s*=\\s*\\1\\[\\w+\\[\\d+\\]\\]\\(\\w+\\[\\d+\\]\\)\\s*,\\s*\\w+\\s*=\\s*\\[.*?\\]\\;.*?catch\\s*\\(\\s*(\\w+)\\s*\\)\\s*\\{return\\s*\\w+\\[\\d+\\]\\s*\\+\\s*\\1\\}\\s*return\\s*\\w+\\[\\w+\\[\\d+\\]\\]\\(\\w+\\[\\d+\\]\\)\\}\\s*\\;";

pub const PATTERN_PREFIX: &str = concatcp!("(?:^|,)\\\"?(", VARIABLE_PART, ")\\\"?");
pub const REVERSE_PATTERN: &str = concatcp!("(?m)", PATTERN_PREFIX, REVERSE_PART);
pub const SLICE_PATTERN: &str = concatcp!("(?m)", PATTERN_PREFIX, SLICE_PART);
pub const SPLICE_PATTERN: &str = concatcp!("(?m)", PATTERN_PREFIX, SPLICE_PART);
pub const SWAP_PATTERN: &str = concatcp!("(?m)", PATTERN_PREFIX, SWAP_PART);

pub const FOR_PARAM_MATCHING: &str = r"function\s*\(\s*(\w+)\s*\)";

pub const DECIPHER_FUNC_NAME: &str = "DisTubeDecipherFunc";
pub const N_TRANSFORM_FUNC_NAME: &str = "DisTubeNTransformFunc";

macro_rules! code_location {
    () => {
        concat!("at ", file!(), ":", line!())
    };
}

macro_rules! invalid_regex_error {
    ($regex_name:ident) => {
        formatcp!(
            "Invalid regex for '{}' {}",
            stringify!($regex_name),
            code_location!()
        )
    };
}

macro_rules! backtrace_error {
    ($regex_name:ident, $input:ident) => {
        formatcp!(
            "Backtrace failed for input '{}' using regex '{}' {}",
            stringify!($input),
            stringify!($regex_name),
            code_location!()
        )
    };
}

macro_rules! no_captures_error {
    ($regex_name:ident, $input:ident) => {
        formatcp!(
            "No captures found for input '{}' using regex '{}' {}",
            stringify!($input),
            stringify!($regex_name),
            code_location!()
        )
    };
}

macro_rules! no_named_capture_error {
    ($regex_name:ident, $group_name:literal, $input:ident) => {
        formatcp!(
            "No capture group named '{}' found for input '{}' using regex '{}' {}",
            concatcp!($group_name),
            stringify!($input),
            stringify!($regex_name),
            code_location!()
        )
    };
}

macro_rules! nth_capture_error {
    ($regex_name:ident, 0, $input:ident) => {
        nth_capture_error!($regex_name, "first", $input)
    };
    ($regex_name:ident, 1, $input:ident) => {
        nth_capture_error!($regex_name, "second", $input)
    };
    ($regex_name:ident, 2, $input:ident) => {
        nth_capture_error!($regex_name, "third", $input)
    };
    ($regex_name:ident, $ordinal:literal, $input:ident) => {
        formatcp!(
            "No {} capture group found for input '{}' using regex '{}' {}",
            concatcp!($ordinal),
            stringify!($input),
            stringify!($regex_name),
            code_location!()
        )
    };
}

macro_rules! build_regex {
    ($name:ident, $type: ty) => {
        build_regex!($name, $type, $name)
    };
    ($name:ident, $type: ty, $flags:literal) => {
        build_regex!($name, $type, concatcp!("(?", $flags, ")", $name))
    };
    ($name:ident, $type: ty, $pattern:expr) => {
        <$type>::new($pattern).map_err(|_| invalid_regex_error!($name))
    };
}

pub struct ExtractTceFunc {
    pub name: String,
    pub code: String,
}

pub fn extract_tce_func(body: &str) -> Result<ExtractTceFunc> {
    let tce_variable_matcher = build_regex!(NEW_TCE_GLOBAL_VARS_REGEXP, Regex, "m")?
        .captures(body)
        .ok_or_else(|| no_captures_error!(NEW_TCE_GLOBAL_VARS_REGEXP, body))?;

    let code = tce_variable_matcher
        .name("code")
        .ok_or_else(|| no_named_capture_error!(NEW_TCE_GLOBAL_VARS_REGEXP, "code", body))?
        .as_str()
        .to_string();
    let varname = tce_variable_matcher
        .name("varname")
        .ok_or_else(|| no_named_capture_error!(NEW_TCE_GLOBAL_VARS_REGEXP, "varname", body))?
        .as_str()
        .to_string();

    Ok(ExtractTceFunc {
        name: varname,
        code,
    })
}

pub fn extract_decipher_func(body: &str, code: &str) -> Result<String> {
    let sig_function_matcher = build_regex!(TCE_SIGN_FUNCTION_REGEXP, FancyRegex, "s")?
        .captures(body)
        .map_err(|_| backtrace_error!(TCE_SIGN_FUNCTION_REGEXP, body))?;
    let sig_function_actions_matcher =
        build_regex!(TCE_SIGN_FUNCTION_ACTION_REGEXP, Regex, "s")?.captures(body);

    if let Some(sig_fn_caps) = sig_function_matcher {
        if let Some(sig_fn_act_caps) = sig_function_actions_matcher {
            return Ok(format!(
                "var {}={}{}{};",
                DECIPHER_FUNC_NAME,
                sig_fn_caps
                    .get(0)
                    .ok_or_else(|| nth_capture_error!(TCE_SIGN_FUNCTION_REGEXP, 0, body))?
                    .as_str(),
                sig_fn_act_caps
                    .get(0)
                    .ok_or_else(|| nth_capture_error!(TCE_SIGN_FUNCTION_ACTION_REGEXP, 0, body))?
                    .as_str(),
                code
            ));
        }
    }

    let helper_match = build_regex!(HELPER_REGEXP, Regex, "s")?
        .captures(body)
        .ok_or_else(|| no_captures_error!(HELPER_REGEXP, body))?;

    let helper_object = helper_match
        .get(0)
        .ok_or_else(|| nth_capture_error!(HELPER_REGEXP, 0, body))?
        .as_str();

    {
        let action_body = helper_match
            .get(2)
            .ok_or_else(|| nth_capture_error!(HELPER_REGEXP, 2, body))?
            .as_str();

        let pattern_regex_set = build_regex!(
            PATTERN_REGEX_SET,
            RegexSet,
            [REVERSE_PATTERN, SLICE_PATTERN, SPLICE_PATTERN, SWAP_PATTERN]
        )?;

        if !pattern_regex_set.is_match(action_body) {
            return Err(no_captures_error!(PATTERN_REGEX_SET, action_body));
        }
    }

    let func_match = build_regex!(DECIPHER_REGEXP, FancyRegex, "s")?
        .captures(body)
        .map_err(|_| backtrace_error!(DECIPHER_REGEXP, body))?;

    let (decipher_func, is_tce) = match func_match {
        Some(fn_caps) => (
            fn_caps
                .get(0)
                .ok_or_else(|| nth_capture_error!(DECIPHER_REGEXP, 0, body))?
                .as_str(),
            false,
        ),
        None => {
            let tce_func_match = build_regex!(FUNCTION_TCE_REGEXP, Regex, "s")?
                .captures(body)
                .ok_or_else(|| no_captures_error!(FUNCTION_TCE_REGEXP, body))?;
            (
                tce_func_match
                    .get(0)
                    .ok_or_else(|| nth_capture_error!(FUNCTION_TCE_REGEXP, 0, body))?
                    .as_str(),
                true,
            )
        }
    };

    let mut tce_vars = "";
    if is_tce {
        let tce_vars_match = build_regex!(TCE_GLOBAL_VARS_REGEXP, FancyRegex, "m")?
            .captures(body)
            .map_err(|_| backtrace_error!(TCE_GLOBAL_VARS_REGEXP, body))?;
        if let Some(tce_vars_caps) = tce_vars_match {
            tce_vars = tce_vars_caps
                .get(1)
                .ok_or_else(|| nth_capture_error!(TCE_GLOBAL_VARS_REGEXP, 1, body))?
                .as_str(); // + ";"
        }
    }

    Ok(format!(
        "{};{}\nvar {}={};",
        tce_vars, helper_object, DECIPHER_FUNC_NAME, decipher_func
    ))
}

pub fn extract_n_transform_func(body: &str, name: &str, code: &str) -> Result<String> {
    let n_function_matcher = build_regex!(TCE_N_FUNCTION_REGEXP, FancyRegex, "s")?
        .captures(body)
        .map_err(|_| backtrace_error!(TCE_N_FUNCTION_REGEXP, body))?;

    if let Some(n_fn_caps) = n_function_matcher {
        let mut n_function = n_fn_caps
            .get(0)
            .ok_or_else(|| nth_capture_error!(TCE_N_FUNCTION_REGEXP, 0, body))?
            .as_str()
            .to_string();

        let tce_escape_name = regex::escape(name);
        let short_circuit_pattern = Regex::new(&format!(
            ";\\s*if\\s*\\(\\s*typeof\\s+[a-zA-Z0-9_$]+\\s*===?\\s*(?:\"undefined\"|'undefined'|{tce_escape_name}\\[\\d+\\])\\s*\\)\\s*return\\s+\\w+;"
        )).map_err(|_| invalid_regex_error!(short_circuit_pattern))?;

        let tce_short_circuit_matcher = short_circuit_pattern.captures(&n_function);

        if let Some(short_circuit_caps) = tce_short_circuit_matcher {
            n_function = n_function.replace(
                short_circuit_caps
                    .get(0)
                    .ok_or_else(|| nth_capture_error!(short_circuit_pattern, 0, n_function))?
                    .as_str(),
                ";",
            );
        }

        return Ok(format!(
            "var {}={}{};",
            N_TRANSFORM_FUNC_NAME, n_function, code
        ));
    }

    let n_match = build_regex!(N_TRANSFORM_REGEXP, FancyRegex, "s")?
        .captures(body)
        .map_err(|_| backtrace_error!(N_TRANSFORM_REGEXP, body))?;

    let (n_function, is_tce) = match n_match {
        Some(n_caps) => (
            n_caps
                .get(0)
                .ok_or_else(|| nth_capture_error!(N_TRANSFORM_REGEXP, 0, body))?
                .as_str(),
            false,
        ),
        None => {
            let n_tce_match = build_regex!(N_TRANSFORM_TCE_REGEXP, FancyRegex, "s")?
                .captures(body)
                .map_err(|_| backtrace_error!(N_TRANSFORM_TCE_REGEXP, body))?
                .ok_or_else(|| no_captures_error!(N_TRANSFORM_TCE_REGEXP, body))?;
            (
                n_tce_match
                    .get(0)
                    .ok_or_else(|| nth_capture_error!(N_TRANSFORM_TCE_REGEXP, 0, body))?
                    .as_str(),
                true,
            )
        }
    };

    let param_match = build_regex!(FOR_PARAM_MATCHING, Regex)?
        .captures(n_function)
        .ok_or_else(|| no_captures_error!(FOR_PARAM_MATCHING, n_function))?;

    let param_name = param_match
        .get(1)
        .ok_or_else(|| nth_capture_error!(FOR_PARAM_MATCHING, 1, n_function))?
        .as_str();

    let cleaned_function = Regex::new(&format!(
        "if\\s*\\(typeof\\s*[^\\s()]+\\s*===?.*?\\)return {param_name}\\s*;?"
    ))
    .map_err(|_| invalid_regex_error!(CLEANED_FUNCTION_REGEXP))?
    .replace_all(n_function, "");

    let mut tce_vars = "";
    if is_tce {
        let tce_vars_match = build_regex!(TCE_GLOBAL_VARS_REGEXP, FancyRegex, "m")?
            .captures(body)
            .map_err(|_| backtrace_error!(TCE_GLOBAL_VARS_REGEXP, body))?;
        if let Some(tce_vars_caps) = tce_vars_match {
            tce_vars = tce_vars_caps
                .get(1)
                .ok_or_else(|| nth_capture_error!(TCE_GLOBAL_VARS_REGEXP, 1, body))?
                .as_str(); // + ";"
        }
    }

    Ok(format!(
        "{};var {}={};",
        tce_vars, N_TRANSFORM_FUNC_NAME, cleaned_function
    ))
}
