// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_cons.h>
#include <string.h>
#include <rz_analysis.h>

#include "../format/java/new/class_bin.h"

//typedef bool (*RzJavaCommand)(RzCmd *cmd, const RzCmdDesc *desc, void *user);
//
//static const RzJavaCommand command_line[] = {
//};

RZ_IPI RzCmdStatus rz_cmd_java_handler(RzCore *core, int argc, const char **argv) {
	if (argc < 2) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	//for (int i = 0; i < END_CMDS; i++) {
	//	if (!strncmp(argv[1], JAVA_CMDS[i].name, JAVA_CMDS[i].name_len)) {
	//		return JAVA_CMDS[i].handler(core, argc - 2, argc > 2 ? &argv[2] : NULL);
	//	}
	//}
	return RZ_CMD_STATUS_WRONG_ARGS;
}

static const char *cmd_java_subcmd_choices[] = { "help", "constants", NULL };
static const RzCmdDescArg cmd_java_args[3] = {
	{
		.name = "subcmd",
		.type = RZ_CMD_ARG_TYPE_CHOICES,
		.default_value = "help",
		.choices = cmd_java_subcmd_choices,
	},
	{
		.name = "arg",
		.type = RZ_CMD_ARG_TYPE_STRING,
		.flags = RZ_CMD_ARG_FLAG_ARRAY,
		.optional = true,
	},
	{ 0 },
};

static const RzCmdDescHelp cmd_java_help = {
	.summary = "Extra commands to visualize java details",
	.description = "Type `java help` for more commands.",
	.args = cmd_java_args,
};

static bool rz_cmd_java_init_handler(RzCore *core) {
	RzCmd *cmd = core->rcmd;
	RzCmdDesc *root_cd = rz_cmd_get_root(cmd);
	if (!root_cd) {
		return false;
	}

	RzCmdDesc *cmd_java_cd = rz_cmd_desc_argv_new(cmd, root_cd, "java", rz_cmd_java_handler, &cmd_java_help);
	rz_warn_if_fail(cmd_java_cd);
	return cmd_java_cd != NULL;
}

RzCorePlugin rz_core_plugin_java = {
	.name = "java",
	.desc = "Suite of java commands, java help for more info",
	.license = "LGPL",
	.author = "deroad",
	.version = "1.0",
	.init = rz_cmd_java_init_handler,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CORE,
	.data = &rz_core_plugin_java,
	.version = RZ_VERSION
};
#endif
