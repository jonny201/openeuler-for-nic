/*
 * Copyright 2020 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: AMD
 *
 */


#include "dm_services.h"
#include "dm_helpers.h"
#include "core_types.h"
#include "resource.h"
#include "dcn30_hwseq.h"
#include "dccg.h"
#include "dce/dce_hwseq.h"
#include "dcn30_mpc.h"
#include "dcn30_dpp.h"
#include "dcn10/dcn10_cm_common.h"
#include "dcn30_cm_common.h"
#include "reg_helper.h"
#include "abm.h"
#include "clk_mgr.h"
#include "hubp.h"
#include "dchubbub.h"
#include "timing_generator.h"
#include "opp.h"
#include "ipp.h"
#include "mpc.h"
#include "mcif_wb.h"
#include "dc_dmub_srv.h"
#include "link_hwss.h"
#include "dpcd_defs.h"




#define DC_LOGGER_INIT(logger)

#define CTX \
	hws->ctx
#define REG(reg)\
	hws->regs->reg
#define DC_LOGGER \
		dc->ctx->logger


#undef FN
#define FN(reg_name, field_name) \
	hws->shifts->field_name, hws->masks->field_name

bool dcn30_set_blend_lut(
	struct pipe_ctx *pipe_ctx, const struct dc_plane_state *plane_state)
{
	struct dpp *dpp_base = pipe_ctx->plane_res.dpp;
	bool result = true;
	struct pwl_params *blend_lut = NULL;

	if (plane_state->blend_tf) {
		if (plane_state->blend_tf->type == TF_TYPE_HWPWL)
			blend_lut = &plane_state->blend_tf->pwl;
		else if (plane_state->blend_tf->type == TF_TYPE_DISTRIBUTED_POINTS) {
			cm3_helper_translate_curve_to_hw_format(
					plane_state->blend_tf, &dpp_base->regamma_params, false);
			blend_lut = &dpp_base->regamma_params;
		}
	}
	result = dpp_base->funcs->dpp_program_blnd_lut(dpp_base, blend_lut);

	return result;
}

static bool dcn30_set_mpc_shaper_3dlut(
	struct pipe_ctx *pipe_ctx, const struct dc_stream_state *stream)
{
	struct dpp *dpp_base = pipe_ctx->plane_res.dpp;
	int mpcc_id = pipe_ctx->plane_res.hubp->inst;
	struct mpc *mpc = pipe_ctx->stream_res.opp->ctx->dc->res_pool->mpc;
	bool result = false;
	int acquired_rmu = 0;
	int mpcc_id_projected = 0;

	const struct pwl_params *shaper_lut = NULL;
	//get the shaper lut params
	if (stream->func_shaper) {
		if (stream->func_shaper->type == TF_TYPE_HWPWL)
			shaper_lut = &stream->func_shaper->pwl;
		else if (stream->func_shaper->type == TF_TYPE_DISTRIBUTED_POINTS) {
			cm_helper_translate_curve_to_hw_format(
					stream->func_shaper,
					&dpp_base->shaper_params, true);
			shaper_lut = &dpp_base->shaper_params;
		}
	}

	if (stream->lut3d_func &&
		stream->lut3d_func->state.bits.initialized == 1 &&
		stream->lut3d_func->state.bits.rmu_idx_valid == 1) {
		if (stream->lut3d_func->state.bits.rmu_mux_num == 0)
			mpcc_id_projected = stream->lut3d_func->state.bits.mpc_rmu0_mux;
		else if (stream->lut3d_func->state.bits.rmu_mux_num == 1)
			mpcc_id_projected = stream->lut3d_func->state.bits.mpc_rmu1_mux;
		else if (stream->lut3d_func->state.bits.rmu_mux_num == 2)
			mpcc_id_projected = stream->lut3d_func->state.bits.mpc_rmu2_mux;
		if (mpcc_id_projected != mpcc_id)
			BREAK_TO_DEBUGGER();
		/*find the reason why logical layer assigned a differant mpcc_id into acquire_post_bldn_3dlut*/
		acquired_rmu = mpc->funcs->acquire_rmu(mpc, mpcc_id,
				stream->lut3d_func->state.bits.rmu_mux_num);
		if (acquired_rmu != stream->lut3d_func->state.bits.rmu_mux_num)
			BREAK_TO_DEBUGGER();
		result = mpc->funcs->program_3dlut(mpc,
								&stream->lut3d_func->lut_3d,
								stream->lut3d_func->state.bits.rmu_mux_num);
		result = mpc->funcs->program_shaper(mpc, shaper_lut,
				stream->lut3d_func->state.bits.rmu_mux_num);
	} else
		/*loop through the available mux and release the requested mpcc_id*/
		mpc->funcs->release_rmu(mpc, mpcc_id);


	return result;
}

bool dcn30_set_input_transfer_func(struct dc *dc,
				struct pipe_ctx *pipe_ctx,
				const struct dc_plane_state *plane_state)
{
	struct dce_hwseq *hws = dc->hwseq;
	struct dpp *dpp_base = pipe_ctx->plane_res.dpp;
	enum dc_transfer_func_predefined tf;
	bool result = true;
	struct pwl_params *params = NULL;

	if (dpp_base == NULL || plane_state == NULL)
		return false;

	tf = TRANSFER_FUNCTION_UNITY;

	if (plane_state->in_transfer_func &&
		plane_state->in_transfer_func->type == TF_TYPE_PREDEFINED)
		tf = plane_state->in_transfer_func->tf;

	dpp_base->funcs->dpp_set_pre_degam(dpp_base, tf);

	if (plane_state->in_transfer_func) {
		if (plane_state->in_transfer_func->type == TF_TYPE_HWPWL)
			params = &plane_state->in_transfer_func->pwl;
		else if (plane_state->in_transfer_func->type == TF_TYPE_DISTRIBUTED_POINTS &&
			cm3_helper_translate_curve_to_hw_format(plane_state->in_transfer_func,
					&dpp_base->degamma_params, false))
			params = &dpp_base->degamma_params;
	}

	result = dpp_base->funcs->dpp_program_gamcor_lut(dpp_base, params);

	if (pipe_ctx->stream_res.opp && pipe_ctx->stream_res.opp->ctx) {
		if (dpp_base->funcs->dpp_program_blnd_lut)
			hws->funcs.set_blend_lut(pipe_ctx, plane_state);
		if (dpp_base->funcs->dpp_program_shaper_lut &&
				dpp_base->funcs->dpp_program_3dlut)
			hws->funcs.set_shaper_3dlut(pipe_ctx, plane_state);
	}

	return result;
}

bool dcn30_set_output_transfer_func(struct dc *dc,
				struct pipe_ctx *pipe_ctx,
				const struct dc_stream_state *stream)
{
	int mpcc_id = pipe_ctx->plane_res.hubp->inst;
	struct mpc *mpc = pipe_ctx->stream_res.opp->ctx->dc->res_pool->mpc;
	struct pwl_params *params = NULL;
	bool ret = false;

	/* program OGAM or 3DLUT only for the top pipe*/
	if (pipe_ctx->top_pipe == NULL) {
		/*program rmu shaper and 3dlut in MPC*/
		ret = dcn30_set_mpc_shaper_3dlut(pipe_ctx, stream);
		if (ret == false && mpc->funcs->set_output_gamma && stream->out_transfer_func) {
			if (stream->out_transfer_func->type == TF_TYPE_HWPWL)
				params = &stream->out_transfer_func->pwl;
			else if (pipe_ctx->stream->out_transfer_func->type ==
					TF_TYPE_DISTRIBUTED_POINTS &&
					cm3_helper_translate_curve_to_hw_format(
					stream->out_transfer_func,
					&mpc->blender_params, false))
				params = &mpc->blender_params;
			 /* there are no ROM LUTs in OUTGAM */
			if (stream->out_transfer_func->type == TF_TYPE_PREDEFINED)
				BREAK_TO_DEBUGGER();
		}
	}

	if (mpc->funcs->set_output_gamma)
		mpc->funcs->set_output_gamma(mpc, mpcc_id, params);
	else
		DC_LOG_ERROR("%s: set_output_gamma function pointer is NULL.\n", __func__);

	return ret;
}

static void dcn30_set_writeback(
		struct dc *dc,
		struct dc_writeback_info *wb_info,
		struct dc_state *context)
{
	struct mcif_wb *mcif_wb;
	struct mcif_buf_params *mcif_buf_params;

	ASSERT(wb_info->dwb_pipe_inst < MAX_DWB_PIPES);
	ASSERT(wb_info->wb_enabled);
	ASSERT(wb_info->mpcc_inst >= 0);
	ASSERT(wb_info->mpcc_inst < dc->res_pool->mpcc_count);
	mcif_wb = dc->res_pool->mcif_wb[wb_info->dwb_pipe_inst];
	mcif_buf_params = &wb_info->mcif_buf_params;

	/* set DWB MPC mux */
	dc->res_pool->mpc->funcs->set_dwb_mux(dc->res_pool->mpc,
			wb_info->dwb_pipe_inst, wb_info->mpcc_inst);
	/* set MCIF_WB buffer and arbitration configuration */
	mcif_wb->funcs->config_mcif_buf(mcif_wb, mcif_buf_params, wb_info->dwb_params.dest_height);
	mcif_wb->funcs->config_mcif_arb(mcif_wb, &context->bw_ctx.bw.dcn.bw_writeback.mcif_wb_arb[wb_info->dwb_pipe_inst]);
}

void dcn30_update_writeback(
		struct dc *dc,
		struct dc_writeback_info *wb_info,
		struct dc_state *context)
{
	struct dwbc *dwb;
	dwb = dc->res_pool->dwbc[wb_info->dwb_pipe_inst];
	DC_LOG_DWB("%s dwb_pipe_inst = %d, mpcc_inst = %d",\
		__func__, wb_info->dwb_pipe_inst,\
		wb_info->mpcc_inst);

	dcn30_set_writeback(dc, wb_info, context);

	/* update DWB */
	dwb->funcs->update(dwb, &wb_info->dwb_params);
}

bool dcn30_mmhubbub_warmup(
	struct dc *dc,
	unsigned int num_dwb,
	struct dc_writeback_info *wb_info)
{
	struct dwbc *dwb;
	struct mcif_wb *mcif_wb;
	struct mcif_warmup_params warmup_params = {0};
	unsigned int  i, i_buf;
	/*make sure there is no active DWB eanbled */
	for (i = 0; i < num_dwb; i++) {
		dwb = dc->res_pool->dwbc[wb_info[i].dwb_pipe_inst];
		if (dwb->dwb_is_efc_transition || dwb->dwb_is_drc) {
			/*can not do warmup while any dwb enabled*/
			return false;
		}
	}

	if (wb_info->mcif_warmup_params.p_vmid == 0)
		return false;

	/*check whether this is new interface: warmup big buffer once*/
	if (wb_info->mcif_warmup_params.start_address.quad_part != 0 &&
		wb_info->mcif_warmup_params.region_size != 0) {
		/*mmhubbub is shared, so it does not matter which MCIF*/
		mcif_wb = dc->res_pool->mcif_wb[0];
		/*warmup a big chunk of VM buffer at once*/
		warmup_params.start_address.quad_part = wb_info->mcif_warmup_params.start_address.quad_part;
		warmup_params.address_increment =  wb_info->mcif_warmup_params.region_size;
		warmup_params.region_size = wb_info->mcif_warmup_params.region_size;
		warmup_params.p_vmid = wb_info->mcif_warmup_params.p_vmid;

		if (warmup_params.address_increment == 0)
			warmup_params.address_increment = dc->dml.soc.vmm_page_size_bytes;

		mcif_wb->funcs->warmup_mcif(mcif_wb, &warmup_params);
		return true;
	}
	/*following is the original: warmup each DWB's mcif buffer*/
	for (i = 0; i < num_dwb; i++) {
		dwb = dc->res_pool->dwbc[wb_info[i].dwb_pipe_inst];
		mcif_wb = dc->res_pool->mcif_wb[wb_info[i].dwb_pipe_inst];
		/*warmup is for VM mode only*/
		if (wb_info[i].mcif_buf_params.p_vmid == 0)
			return false;

		/* Warmup MCIF_WB */
		for (i_buf = 0; i_buf < MCIF_BUF_COUNT; i_buf++) {
			warmup_params.start_address.quad_part = wb_info[i].mcif_buf_params.luma_address[i_buf];
			warmup_params.address_increment = dc->dml.soc.vmm_page_size_bytes;
			warmup_params.region_size = wb_info[i].mcif_buf_params.luma_pitch * wb_info[i].dwb_params.dest_height;
			warmup_params.p_vmid = wb_info[i].mcif_buf_params.p_vmid;
			mcif_wb->funcs->warmup_mcif(mcif_wb, &warmup_params);
		}
	}
	return true;
}

void dcn30_enable_writeback(
		struct dc *dc,
		struct dc_writeback_info *wb_info,
		struct dc_state *context)
{
	struct dwbc *dwb;
	struct mcif_wb *mcif_wb;
	struct timing_generator *optc;

	dwb = dc->res_pool->dwbc[wb_info->dwb_pipe_inst];
	mcif_wb = dc->res_pool->mcif_wb[wb_info->dwb_pipe_inst];

	/* set the OPTC source mux */
	optc = dc->res_pool->timing_generators[dwb->otg_inst];
	DC_LOG_DWB("%s dwb_pipe_inst = %d, mpcc_inst = %d",\
		__func__, wb_info->dwb_pipe_inst,\
		wb_info->mpcc_inst);
	if (IS_DIAG_DC(dc->ctx->dce_environment)) {
		/*till diags switch to warmup interface*/
		dcn30_mmhubbub_warmup(dc, 1, wb_info);
	}
	/* Update writeback pipe */
	dcn30_set_writeback(dc, wb_info, context);

	/* Enable MCIF_WB */
	mcif_wb->funcs->enable_mcif(mcif_wb);
	/* Enable DWB */
	dwb->funcs->enable(dwb, &wb_info->dwb_params);
}

void dcn30_disable_writeback(
		struct dc *dc,
		unsigned int dwb_pipe_inst)
{
	struct dwbc *dwb;
	struct mcif_wb *mcif_wb;

	ASSERT(dwb_pipe_inst < MAX_DWB_PIPES);
	dwb = dc->res_pool->dwbc[dwb_pipe_inst];
	mcif_wb = dc->res_pool->mcif_wb[dwb_pipe_inst];
	DC_LOG_DWB("%s dwb_pipe_inst = %d",\
		__func__, dwb_pipe_inst);

	/* disable DWB */
	dwb->funcs->disable(dwb);
	/* disable MCIF */
	mcif_wb->funcs->disable_mcif(mcif_wb);
	/* disable MPC DWB mux */
	dc->res_pool->mpc->funcs->disable_dwb_mux(dc->res_pool->mpc, dwb_pipe_inst);
}

void dcn30_program_all_writeback_pipes_in_tree(
		struct dc *dc,
		const struct dc_stream_state *stream,
		struct dc_state *context)
{
	struct dc_writeback_info wb_info;
	struct dwbc *dwb;
	struct dc_stream_status *stream_status = NULL;
	int i_wb, i_pipe, i_stream;
	DC_LOG_DWB("%s", __func__);

	ASSERT(stream);
	for (i_stream = 0; i_stream < context->stream_count; i_stream++) {
		if (context->streams[i_stream] == stream) {
			stream_status = &context->stream_status[i_stream];
			break;
		}
	}
	ASSERT(stream_status);

	ASSERT(stream->num_wb_info <= dc->res_pool->res_cap->num_dwb);
	/* For each writeback pipe */
	for (i_wb = 0; i_wb < stream->num_wb_info; i_wb++) {

		/* copy writeback info to local non-const so mpcc_inst can be set */
		wb_info = stream->writeback_info[i_wb];
		if (wb_info.wb_enabled) {

			/* get the MPCC instance for writeback_source_plane */
			wb_info.mpcc_inst = -1;
			for (i_pipe = 0; i_pipe < dc->res_pool->pipe_count; i_pipe++) {
				struct pipe_ctx *pipe_ctx = &context->res_ctx.pipe_ctx[i_pipe];

				if (!pipe_ctx->plane_state)
					continue;

				if (pipe_ctx->plane_state == wb_info.writeback_source_plane) {
					wb_info.mpcc_inst = pipe_ctx->plane_res.mpcc_inst;
					break;
				}
			}

			if (wb_info.mpcc_inst == -1) {
				/* Disable writeback pipe and disconnect from MPCC
				 * if source plane has been removed
				 */
				dc->hwss.disable_writeback(dc, wb_info.dwb_pipe_inst);
				continue;
			}

			ASSERT(wb_info.dwb_pipe_inst < dc->res_pool->res_cap->num_dwb);
			dwb = dc->res_pool->dwbc[wb_info.dwb_pipe_inst];
			if (dwb->funcs->is_enabled(dwb)) {
				/* writeback pipe already enabled, only need to update */
				dc->hwss.update_writeback(dc, &wb_info, context);
			} else {
				/* Enable writeback pipe and connect to MPCC */
				dc->hwss.enable_writeback(dc, &wb_info, context);
			}
		} else {
			/* Disable writeback pipe and disconnect from MPCC */
			dc->hwss.disable_writeback(dc, wb_info.dwb_pipe_inst);
		}
	}
}

void dcn30_init_hw(struct dc *dc)
{
	int i, j;
	struct abm **abms = dc->res_pool->multiple_abms;
	struct dce_hwseq *hws = dc->hwseq;
	struct dc_bios *dcb = dc->ctx->dc_bios;
	struct resource_pool *res_pool = dc->res_pool;
	uint32_t backlight = MAX_BACKLIGHT_LEVEL;

	if (dc->clk_mgr && dc->clk_mgr->funcs && dc->clk_mgr->funcs->init_clocks)
		dc->clk_mgr->funcs->init_clocks(dc->clk_mgr);

	// Initialize the dccg
	if (res_pool->dccg->funcs->dccg_init)
		res_pool->dccg->funcs->dccg_init(res_pool->dccg);

	if (IS_FPGA_MAXIMUS_DC(dc->ctx->dce_environment)) {

		REG_WRITE(REFCLK_CNTL, 0);
		REG_UPDATE(DCHUBBUB_GLOBAL_TIMER_CNTL, DCHUBBUB_GLOBAL_TIMER_ENABLE, 1);
		REG_WRITE(DIO_MEM_PWR_CTRL, 0);

		if (!dc->debug.disable_clock_gate) {
			/* enable all DCN clock gating */
			REG_WRITE(DCCG_GATE_DISABLE_CNTL, 0);

			REG_WRITE(DCCG_GATE_DISABLE_CNTL2, 0);

			REG_UPDATE(DCFCLK_CNTL, DCFCLK_GATE_DIS, 0);
		}

		//Enable ability to power gate / don't force power on permanently
		if (hws->funcs.enable_power_gating_plane)
			hws->funcs.enable_power_gating_plane(hws, true);

		return;
	}

	if (!dcb->funcs->is_accelerated_mode(dcb)) {
		hws->funcs.bios_golden_init(dc);
		hws->funcs.disable_vga(dc->hwseq);
	}

	if (dc->ctx->dc_bios->fw_info_valid) {
		res_pool->ref_clocks.xtalin_clock_inKhz =
				dc->ctx->dc_bios->fw_info.pll_info.crystal_frequency;

		if (!IS_FPGA_MAXIMUS_DC(dc->ctx->dce_environment)) {
			if (res_pool->dccg && res_pool->hubbub) {

				(res_pool->dccg->funcs->get_dccg_ref_freq)(res_pool->dccg,
						dc->ctx->dc_bios->fw_info.pll_info.crystal_frequency,
						&res_pool->ref_clocks.dccg_ref_clock_inKhz);

				(res_pool->hubbub->funcs->get_dchub_ref_freq)(res_pool->hubbub,
						res_pool->ref_clocks.dccg_ref_clock_inKhz,
						&res_pool->ref_clocks.dchub_ref_clock_inKhz);
			} else {
				// Not all ASICs have DCCG sw component
				res_pool->ref_clocks.dccg_ref_clock_inKhz =
						res_pool->ref_clocks.xtalin_clock_inKhz;
				res_pool->ref_clocks.dchub_ref_clock_inKhz =
						res_pool->ref_clocks.xtalin_clock_inKhz;
			}
		}
	} else
		ASSERT_CRITICAL(false);

	for (i = 0; i < dc->link_count; i++) {
		/* Power up AND update implementation according to the
		 * required signal (which may be different from the
		 * default signal on connector).
		 */
		struct dc_link *link = dc->links[i];

		link->link_enc->funcs->hw_init(link->link_enc);

		/* Check for enabled DIG to identify enabled display */
		if (link->link_enc->funcs->is_dig_enabled &&
			link->link_enc->funcs->is_dig_enabled(link->link_enc))
			link->link_status.link_active = true;
	}

	/* Power gate DSCs */
	for (i = 0; i < res_pool->res_cap->num_dsc; i++)
		if (hws->funcs.dsc_pg_control != NULL)
			hws->funcs.dsc_pg_control(hws, res_pool->dscs[i]->inst, false);

	/* we want to turn off all dp displays before doing detection */
	if (dc->config.power_down_display_on_boot) {
		uint8_t dpcd_power_state = '\0';
		enum dc_status status = DC_ERROR_UNEXPECTED;

		for (i = 0; i < dc->link_count; i++) {
			if (dc->links[i]->connector_signal != SIGNAL_TYPE_DISPLAY_PORT)
				continue;

			/* if any of the displays are lit up turn them off */
			status = core_link_read_dpcd(dc->links[i], DP_SET_POWER,
						     &dpcd_power_state, sizeof(dpcd_power_state));
			if (status == DC_OK && dpcd_power_state == DP_POWER_STATE_D0) {
				/* blank dp stream before power off receiver*/
				if (dc->links[i]->link_enc->funcs->get_dig_frontend) {
					unsigned int fe;

					fe = dc->links[i]->link_enc->funcs->get_dig_frontend(
										dc->links[i]->link_enc);
					if (fe == ENGINE_ID_UNKNOWN)
						continue;

					for (j = 0; j < dc->res_pool->stream_enc_count; j++) {
						if (fe == dc->res_pool->stream_enc[j]->id) {
							dc->res_pool->stream_enc[j]->funcs->dp_blank(
										dc->res_pool->stream_enc[j]);
							break;
						}
					}
				}
				dp_receiver_power_ctrl(dc->links[i], false);
			}
		}
	}

	/* If taking control over from VBIOS, we may want to optimize our first
	 * mode set, so we need to skip powering down pipes until we know which
	 * pipes we want to use.
	 * Otherwise, if taking control is not possible, we need to power
	 * everything down.
	 */
	if (dcb->funcs->is_accelerated_mode(dcb) || dc->config.power_down_display_on_boot) {
		hws->funcs.init_pipes(dc, dc->current_state);
		if (dc->res_pool->hubbub->funcs->allow_self_refresh_control)
			dc->res_pool->hubbub->funcs->allow_self_refresh_control(dc->res_pool->hubbub,
					!dc->res_pool->hubbub->ctx->dc->debug.disable_stutter);
	}

	/* In headless boot cases, DIG may be turned
	 * on which causes HW/SW discrepancies.
	 * To avoid this, power down hardware on boot
	 * if DIG is turned on and seamless boot not enabled
	 */
	if (dc->config.power_down_display_on_boot) {
		struct dc_link *edp_link = get_edp_link(dc);

		if (edp_link &&
				edp_link->link_enc->funcs->is_dig_enabled &&
				edp_link->link_enc->funcs->is_dig_enabled(edp_link->link_enc) &&
				dc->hwss.edp_backlight_control &&
				dc->hwss.power_down &&
				dc->hwss.edp_power_control) {
			dc->hwss.edp_backlight_control(edp_link, false);
			dc->hwss.power_down(dc);
			dc->hwss.edp_power_control(edp_link, false);
		} else {
			for (i = 0; i < dc->link_count; i++) {
				struct dc_link *link = dc->links[i];

				if (link->link_enc->funcs->is_dig_enabled &&
						link->link_enc->funcs->is_dig_enabled(link->link_enc) &&
						dc->hwss.power_down) {
					dc->hwss.power_down(dc);
					break;
				}

			}
		}
	}

	for (i = 0; i < res_pool->audio_count; i++) {
		struct audio *audio = res_pool->audios[i];

		audio->funcs->hw_init(audio);
	}

	for (i = 0; i < dc->link_count; i++) {
		struct dc_link *link = dc->links[i];

		if (link->panel_cntl)
			backlight = link->panel_cntl->funcs->hw_init(link->panel_cntl);
	}

	for (i = 0; i < dc->res_pool->pipe_count; i++) {
		if (abms[i] != NULL)
			abms[i]->funcs->abm_init(abms[i], backlight);
	}

	/* power AFMT HDMI memory TODO: may move to dis/en output save power*/
	REG_WRITE(DIO_MEM_PWR_CTRL, 0);

	if (!dc->debug.disable_clock_gate) {
		/* enable all DCN clock gating */
		REG_WRITE(DCCG_GATE_DISABLE_CNTL, 0);

		REG_WRITE(DCCG_GATE_DISABLE_CNTL2, 0);

		REG_UPDATE(DCFCLK_CNTL, DCFCLK_GATE_DIS, 0);
	}
	if (hws->funcs.enable_power_gating_plane)
		hws->funcs.enable_power_gating_plane(dc->hwseq, true);

	if (dc->clk_mgr && dc->clk_mgr->funcs && dc->clk_mgr->funcs->notify_wm_ranges)
		dc->clk_mgr->funcs->notify_wm_ranges(dc->clk_mgr);

	if (dc->clk_mgr && dc->clk_mgr->funcs && dc->clk_mgr->funcs->set_hard_max_memclk)
		dc->clk_mgr->funcs->set_hard_max_memclk(dc->clk_mgr);
}

void dcn30_set_avmute(struct pipe_ctx *pipe_ctx, bool enable)
{
	if (pipe_ctx == NULL)
		return;

	if (dc_is_hdmi_tmds_signal(pipe_ctx->stream->signal) && pipe_ctx->stream_res.stream_enc != NULL) {
		pipe_ctx->stream_res.stream_enc->funcs->set_avmute(
				pipe_ctx->stream_res.stream_enc,
				enable);

		/* Wait for two frame to make sure AV mute is sent out */
		if (enable) {
			pipe_ctx->stream_res.tg->funcs->wait_for_state(pipe_ctx->stream_res.tg, CRTC_STATE_VACTIVE);
			pipe_ctx->stream_res.tg->funcs->wait_for_state(pipe_ctx->stream_res.tg, CRTC_STATE_VBLANK);
			pipe_ctx->stream_res.tg->funcs->wait_for_state(pipe_ctx->stream_res.tg, CRTC_STATE_VACTIVE);
			pipe_ctx->stream_res.tg->funcs->wait_for_state(pipe_ctx->stream_res.tg, CRTC_STATE_VBLANK);
			pipe_ctx->stream_res.tg->funcs->wait_for_state(pipe_ctx->stream_res.tg, CRTC_STATE_VACTIVE);
		}
	}
}

void dcn30_update_info_frame(struct pipe_ctx *pipe_ctx)
{
	bool is_hdmi_tmds;
	bool is_dp;

	ASSERT(pipe_ctx->stream);

	if (pipe_ctx->stream_res.stream_enc == NULL)
		return;  /* this is not root pipe */

	is_hdmi_tmds = dc_is_hdmi_tmds_signal(pipe_ctx->stream->signal);
	is_dp = dc_is_dp_signal(pipe_ctx->stream->signal);

	if (!is_hdmi_tmds)
		return;

	if (is_hdmi_tmds)
		pipe_ctx->stream_res.stream_enc->funcs->update_hdmi_info_packets(
			pipe_ctx->stream_res.stream_enc,
			&pipe_ctx->stream_res.encoder_info_frame);
	else
		pipe_ctx->stream_res.stream_enc->funcs->update_dp_info_packets(
			pipe_ctx->stream_res.stream_enc,
			&pipe_ctx->stream_res.encoder_info_frame);
}

void dcn30_program_dmdata_engine(struct pipe_ctx *pipe_ctx)
{
	struct dc_stream_state    *stream     = pipe_ctx->stream;
	struct hubp               *hubp       = pipe_ctx->plane_res.hubp;
	bool                       enable     = false;
	struct stream_encoder     *stream_enc = pipe_ctx->stream_res.stream_enc;
	enum dynamic_metadata_mode mode       = dc_is_dp_signal(stream->signal)
							? dmdata_dp
							: dmdata_hdmi;

	/* if using dynamic meta, don't set up generic infopackets */
	if (pipe_ctx->stream->dmdata_address.quad_part != 0) {
		pipe_ctx->stream_res.encoder_info_frame.hdrsmd.valid = false;
		enable = true;
	}

	if (!hubp)
		return;

	if (!stream_enc || !stream_enc->funcs->set_dynamic_metadata)
		return;

	stream_enc->funcs->set_dynamic_metadata(stream_enc, enable,
							hubp->inst, mode);
}

bool dcn30_apply_idle_power_optimizations(struct dc *dc, bool enable)
{
	if (!dc->ctx->dmub_srv)
		return false;

	if (enable) {
		if (dc->current_state) {
			int i;

			/* First, check no-memory-requests case */
			for (i = 0; i < dc->current_state->stream_count; i++) {
				if (dc->current_state->stream_status[i]
					    .plane_count)
					/* Fail eligibility on a visible stream */
					break;
			}
		}

		/* No applicable optimizations */
		return false;
	}

	return true;
}
