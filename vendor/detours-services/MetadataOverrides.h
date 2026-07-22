// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "FileAccessHelpers.h"

// Functions for overriding file metadata based on policy.

// Removes the short file name from directory-entry data (simulate short file names disabled on the volume).
// TODO: Could scrub FILE_ID_BOTH_DIR_INFO too (https://msdn.microsoft.com/en-us/library/windows/desktop/aa364226(v=vs.85).aspx)
void ScrubShortFileName(WIN32_FIND_DATAW* result);
