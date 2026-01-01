# bphook
Hardware-breakpoint-based hooking and patching library for iOS.  
works on jailed and jailbroken device.  
Only 6 hooks or patches can be active at once.

## Usage
See `Tweak.xm` for hook and patch usage.



### Notes
- `BPInit()` must succeed before any other API calls.
- The original function is not called automatically; call `BPhook_call_original(ctx)` in your
  callback when you want to run it.
- `patch_fn` must be a naked AArch64 function and must not `ret`.
- End `patch_fn` with `BP_PATCH_END()`.
- PC-relative branches, PC-relative memory access, or SP-dependent instructions are not supported.
- `x17` is reserved internally and is not preserved.
- Integer/pointer args use x0-x7 (`GET_ARG` index counts only int/ptr args).
- Float/double args use q0-q7 (`GET_FLOAT_ARG`/`GET_DOUBLE_ARG` index counts only fp args).



## License
[MIT License](./LICENSE)  
