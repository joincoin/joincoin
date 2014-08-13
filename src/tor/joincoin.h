/* Copyright (c) 2014, Joincoin Developers */
/* See LICENSE for licensing information */

/**
 * \file joincoin.h
 * \brief Headers for joincoin.cpp
 **/

#ifndef TOR_JOINCOIN_H
#define TOR_JOINCOIN_H

#ifdef __cplusplus
extern "C" {
#endif

    char const* joincoin_tor_data_directory(
    );

    char const* joincoin_service_directory(
    );

    int check_interrupted(
    );

    void set_initialized(
    );

    void wait_initialized(
    );

#ifdef __cplusplus
}
#endif

#endif

