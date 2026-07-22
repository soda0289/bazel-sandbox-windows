// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "stdafx.h"
#include "MetadataOverrides.h"

void ScrubShortFileName(WIN32_FIND_DATAW* result) {
    ZeroMemory(&(result->cAlternateFileName[0]), sizeof(result->cAlternateFileName));
}
