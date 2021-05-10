echo off
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\Tools\VsDevCmd.bat" (
  call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\Tools\VsDevCmd.bat" -host_arch=amd64 -arch=amd64
  call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\Tools\VsDevCmd.bat" -test
) else (
  if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat" -host_arch=amd64 -arch=amd64
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Comuunity\Common7\Tools\VsDevCmd.bat" -test
  ) else (
    if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\Tools\VsDevCmd.bat" (
      call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\Tools\VsDevCmd.bat" -host_arch=amd64 -arch=amd64
      call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\Tools\VsDevCmd.bat" -test
    ) else (
      ECHO "Error: Could not find Visual Studio."
      goto :error
    )
  )
)
ls
cd /d %~dp0
echo "pwd: " %~dp0
ls
cl *.c /I ../kremlin/include /I . /I ../kremlin/kremlib/dist/minimal /c /DHACL_CAN_COMPILE_INTRINSICS /DHACL_CAN_COMPILE_VALE /DHACL_CAN_COMPILE_VEC128 /DHACL_CAN_COMPILE_VEC256 || goto :error
for /F %%i in ('dir /b *-x86_64-msvc.asm') do (
  ml64 /c %%i || goto :error
)
lib /out:libevercrypt.lib *.obj || goto :error
echo "SUCCESS"
exit /b 0

:error
echo "Failed"
exit /b %errorlevel%
