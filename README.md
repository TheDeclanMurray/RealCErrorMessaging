# RealCErrorMessaging

```bash
cd ~/src
git clone https://github.com/davea42/libdwarf-code.git
mkdir -p ~/build/libdwarf
cd ~/build/libdwarf
cmake -G "Unix Makefiles" -DCMAKE_INSTALL_PREFIX="$HOME/local" ~/src/libdwarf-code
make
make install
```

### Install libdwarf

You need to install libdwarf before building this project.

1. Go to your source directory:

   ```bash
   cd ~/src
   ```

2. Clone libdwarf:

   ```bash
   git clone https://github.com/davea42/libdwarf-code.git
   ```

3. Go to your build directory:

   ```bash
   cd ~/build/libdwarf
   ```

4. Configure the build:

   ```bash
   cmake -G "Unix Makefiles" -DCMAKE_INSTALL_PREFIX="$HOME/local" ~/src/libdwarf-code
   ```

   ```bash
   cmake -G "Unix Makefiles" \
      -DCMAKE_INSTALL_PREFIX="$HOME/local" \
      -DBUILD_SHARED=YES \
      -DBUILD_NON_SHARED=NO \
      ~/src/libdwarf-code
   ```

5. Build and install:

   ```bash
   make
   make install
   ```