#pragma once

#include <string>
#include "hh_params.h"

bool load_config(const std::string& ini_path, t_hh_params& params);
bool save_default_config(const std::string& ini_path);
std::string get_config_path();
