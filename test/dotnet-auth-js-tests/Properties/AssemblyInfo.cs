// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

// Caused OOM test issues with file watcher. See https://github.com/aspnet/Identity/issues/1926
// [assembly: CollectionBehavior(DisableTestParallelization = true)]
[assembly: Xunit.TestFramework("Microsoft.AspNetCore.Testing.AspNetTestFramework", "Microsoft.AspNetCore.Testing")]
[assembly: Microsoft.AspNetCore.Testing.AssemblyTestLogFixture]
[assembly: Microsoft.AspNetCore.Testing.TestFrameworkFileLogger("false", "net8.0")]