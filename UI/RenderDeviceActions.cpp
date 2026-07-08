#include "RenderDeviceActions.h"

// This implementation file is included from ImGuiApp.cpp inside the private ImGuiApp class definition.
// D3D device pointers, render target, icon cache, and texture ownership remain owned by ImGuiApp.
        bool CreateDeviceD3D()
        {
            DXGI_SWAP_CHAIN_DESC swapChainDescription = {};
            swapChainDescription.BufferCount = 2;
            swapChainDescription.BufferDesc.Width = 0;
            swapChainDescription.BufferDesc.Height = 0;
            swapChainDescription.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
            swapChainDescription.BufferDesc.RefreshRate.Numerator = 60;
            swapChainDescription.BufferDesc.RefreshRate.Denominator = 1;
            swapChainDescription.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
            swapChainDescription.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
            swapChainDescription.OutputWindow = hwnd_;
            swapChainDescription.SampleDesc.Count = 1;
            swapChainDescription.SampleDesc.Quality = 0;
            swapChainDescription.Windowed = TRUE;
            swapChainDescription.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

            constexpr D3D_FEATURE_LEVEL featureLevels[] = {
                D3D_FEATURE_LEVEL_11_0,
                D3D_FEATURE_LEVEL_10_0
            };

            const HRESULT result = D3D11CreateDeviceAndSwapChain(
                nullptr,
                D3D_DRIVER_TYPE_HARDWARE,
                nullptr,
                0,
                featureLevels,
                ARRAYSIZE(featureLevels),
                D3D11_SDK_VERSION,
                &swapChainDescription,
                &swapChain_,
                &device_,
                nullptr,
                &deviceContext_);

            if (FAILED(result))
            {
                return false;
            }

            CreateRenderTarget();
            return true;
        }

        void CreateRenderTarget()
        {
            ID3D11Texture2D* backBuffer = nullptr;
            if (SUCCEEDED(swapChain_->GetBuffer(0, IID_PPV_ARGS(&backBuffer))))
            {
                device_->CreateRenderTargetView(backBuffer, nullptr, &renderTargetView_);
                backBuffer->Release();
            }
        }

        void CleanupRenderTarget()
        {
            if (renderTargetView_ != nullptr)
            {
                renderTargetView_->Release();
                renderTargetView_ = nullptr;
            }
        }

        void ResizeRenderTarget(UINT width, UINT height)
        {
            CleanupRenderTarget();
            swapChain_->ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }

        void CleanupDeviceD3D()
        {
            CleanupRenderTarget();
            if (swapChain_ != nullptr)
            {
                swapChain_->Release();
                swapChain_ = nullptr;
            }
            if (deviceContext_ != nullptr)
            {
                deviceContext_->Release();
                deviceContext_ = nullptr;
            }
            if (device_ != nullptr)
            {
                device_->Release();
                device_ = nullptr;
            }
        }

        ID3D11ShaderResourceView* GetProcessIconTexture(const Core::ProcessInfo& process)
        {
            const std::wstring cacheKey = process.executablePath.empty()
                ? L"__glasspane_default_icon__"
                : ToLower(process.executablePath);

            const auto cached = iconCache_.find(cacheKey);
            if (cached != iconCache_.end())
            {
                return cached->second.texture;
            }

            ID3D11ShaderResourceView* texture = nullptr;
            bool ownsTexture = false;

            HICON extractedIcon = nullptr;
            if (!process.executablePath.empty())
            {
                HICON largeIcon = nullptr;
                if (ExtractIconExW(process.executablePath.c_str(), 0, &largeIcon, nullptr, 1) > 0 && largeIcon != nullptr)
                {
                    extractedIcon = largeIcon;
                }
            }

            if (extractedIcon != nullptr)
            {
                texture = CreateTextureFromIcon(extractedIcon);
                DestroyIcon(extractedIcon);
                ownsTexture = texture != nullptr;
            }

            if (texture == nullptr)
            {
                texture = GetFallbackIconTexture();
                ownsTexture = false;
            }

            iconCache_[cacheKey] = { texture, ownsTexture };
            return texture;
        }

        ID3D11ShaderResourceView* GetFallbackIconTexture()
        {
            if (fallbackIconTexture_ != nullptr)
            {
                return fallbackIconTexture_;
            }

            HICON fallbackIcon = LoadGlassPaneIcon(instance_, 32, 32);
            fallbackIconTexture_ = CreateTextureFromIcon(fallbackIcon);
            return fallbackIconTexture_;
        }

        ID3D11ShaderResourceView* GetAppLogoTexture()
        {
            if (appLogoTexture_ != nullptr)
            {
                return appLogoTexture_;
            }

            appLogoTexture_ = CreateTextureFromPngResource(IDB_GLASSPANE_LOGO_PNG);
            if (appLogoTexture_ == nullptr)
            {
                appLogoTexture_ = CreateTextureFromIcon(LoadGlassPaneIcon(instance_, 32, 32));
            }
            return appLogoTexture_;
        }

        ID3D11ShaderResourceView* CreateTextureFromPngResource(UINT resourceId) const
        {
            if (device_ == nullptr)
            {
                return nullptr;
            }

            HRSRC resource = FindResourceW(instance_, MAKEINTRESOURCEW(resourceId), RT_RCDATA);
            if (resource == nullptr)
            {
                return nullptr;
            }

            HGLOBAL loadedResource = LoadResource(instance_, resource);
            const DWORD resourceSize = SizeofResource(instance_, resource);
            void* resourceData = LockResource(loadedResource);
            if (loadedResource == nullptr || resourceData == nullptr || resourceSize == 0)
            {
                return nullptr;
            }

            Microsoft::WRL::ComPtr<IWICImagingFactory> factory;
            HRESULT result = CoCreateInstance(
                CLSID_WICImagingFactory,
                nullptr,
                CLSCTX_INPROC_SERVER,
                IID_PPV_ARGS(&factory));
            if (FAILED(result))
            {
                return nullptr;
            }

            Microsoft::WRL::ComPtr<IWICStream> stream;
            result = factory->CreateStream(&stream);
            if (FAILED(result))
            {
                return nullptr;
            }

            result = stream->InitializeFromMemory(
                static_cast<BYTE*>(resourceData),
                resourceSize);
            if (FAILED(result))
            {
                return nullptr;
            }

            Microsoft::WRL::ComPtr<IWICBitmapDecoder> decoder;
            result = factory->CreateDecoderFromStream(
                stream.Get(),
                nullptr,
                WICDecodeMetadataCacheOnLoad,
                &decoder);
            if (FAILED(result))
            {
                return nullptr;
            }

            Microsoft::WRL::ComPtr<IWICBitmapFrameDecode> frame;
            result = decoder->GetFrame(0, &frame);
            if (FAILED(result))
            {
                return nullptr;
            }

            Microsoft::WRL::ComPtr<IWICFormatConverter> converter;
            result = factory->CreateFormatConverter(&converter);
            if (FAILED(result))
            {
                return nullptr;
            }

            result = converter->Initialize(
                frame.Get(),
                GUID_WICPixelFormat32bppRGBA,
                WICBitmapDitherTypeNone,
                nullptr,
                0.0,
                WICBitmapPaletteTypeCustom);
            if (FAILED(result))
            {
                return nullptr;
            }

            UINT width = 0;
            UINT height = 0;
            result = converter->GetSize(&width, &height);
            if (FAILED(result) || width == 0 || height == 0)
            {
                return nullptr;
            }

            const UINT stride = width * 4;
            std::vector<BYTE> pixels(static_cast<std::size_t>(stride) * height);
            result = converter->CopyPixels(nullptr, stride, static_cast<UINT>(pixels.size()), pixels.data());
            if (FAILED(result))
            {
                return nullptr;
            }

            return CreateTextureFromRgbaPixels(pixels.data(), width, height, stride);
        }

        ID3D11ShaderResourceView* CreateTextureFromRgbaPixels(
            const void* pixels,
            UINT width,
            UINT height,
            UINT stride) const
        {
            if (device_ == nullptr || pixels == nullptr || width == 0 || height == 0 || stride == 0)
            {
                return nullptr;
            }

            D3D11_TEXTURE2D_DESC textureDescription = {};
            textureDescription.Width = width;
            textureDescription.Height = height;
            textureDescription.MipLevels = 1;
            textureDescription.ArraySize = 1;
            textureDescription.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
            textureDescription.SampleDesc.Count = 1;
            textureDescription.Usage = D3D11_USAGE_DEFAULT;
            textureDescription.BindFlags = D3D11_BIND_SHADER_RESOURCE;

            D3D11_SUBRESOURCE_DATA initialData = {};
            initialData.pSysMem = pixels;
            initialData.SysMemPitch = stride;

            ID3D11Texture2D* texture = nullptr;
            ID3D11ShaderResourceView* textureView = nullptr;
            if (SUCCEEDED(device_->CreateTexture2D(&textureDescription, &initialData, &texture)))
            {
                if (FAILED(device_->CreateShaderResourceView(texture, nullptr, &textureView)))
                {
                    textureView = nullptr;
                }
                texture->Release();
            }

            return textureView;
        }

        ID3D11ShaderResourceView* CreateTextureFromIcon(HICON icon) const
        {
            if (icon == nullptr || device_ == nullptr)
            {
                return nullptr;
            }

            constexpr int iconSize = 32;
            BITMAPINFO bitmapInfo = {};
            bitmapInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
            bitmapInfo.bmiHeader.biWidth = iconSize;
            bitmapInfo.bmiHeader.biHeight = -iconSize;
            bitmapInfo.bmiHeader.biPlanes = 1;
            bitmapInfo.bmiHeader.biBitCount = 32;
            bitmapInfo.bmiHeader.biCompression = BI_RGB;

            HDC screenDc = GetDC(nullptr);
            if (screenDc == nullptr)
            {
                return nullptr;
            }

            void* bits = nullptr;
            HBITMAP bitmap = CreateDIBSection(screenDc, &bitmapInfo, DIB_RGB_COLORS, &bits, nullptr, 0);
            if (bitmap == nullptr || bits == nullptr)
            {
                if (bitmap != nullptr)
                {
                    DeleteObject(bitmap);
                }
                ReleaseDC(nullptr, screenDc);
                return nullptr;
            }

            HDC memoryDc = CreateCompatibleDC(screenDc);
            if (memoryDc == nullptr)
            {
                DeleteObject(bitmap);
                ReleaseDC(nullptr, screenDc);
                return nullptr;
            }

            HGDIOBJ oldBitmap = SelectObject(memoryDc, bitmap);
            std::memset(bits, 0, static_cast<std::size_t>(iconSize * iconSize * 4));
            DrawIconEx(memoryDc, 0, 0, icon, iconSize, iconSize, 0, nullptr, DI_NORMAL);
            SelectObject(memoryDc, oldBitmap);

            D3D11_TEXTURE2D_DESC textureDescription = {};
            textureDescription.Width = iconSize;
            textureDescription.Height = iconSize;
            textureDescription.MipLevels = 1;
            textureDescription.ArraySize = 1;
            textureDescription.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
            textureDescription.SampleDesc.Count = 1;
            textureDescription.Usage = D3D11_USAGE_DEFAULT;
            textureDescription.BindFlags = D3D11_BIND_SHADER_RESOURCE;

            D3D11_SUBRESOURCE_DATA initialData = {};
            initialData.pSysMem = bits;
            initialData.SysMemPitch = iconSize * 4;

            ID3D11Texture2D* texture = nullptr;
            ID3D11ShaderResourceView* textureView = nullptr;
            if (SUCCEEDED(device_->CreateTexture2D(&textureDescription, &initialData, &texture)) && texture != nullptr)
            {
                if (FAILED(device_->CreateShaderResourceView(texture, nullptr, &textureView)))
                {
                    textureView = nullptr;
                }
                texture->Release();
            }

            DeleteDC(memoryDc);
            DeleteObject(bitmap);
            ReleaseDC(nullptr, screenDc);

            return textureView;
        }

        void ReleaseIconCache()
        {
            for (auto& [path, icon] : iconCache_)
            {
                (void)path;
                if (icon.ownsTexture && icon.texture != nullptr)
                {
                    icon.texture->Release();
                    icon.texture = nullptr;
                }
            }
            iconCache_.clear();

            if (fallbackIconTexture_ != nullptr)
            {
                fallbackIconTexture_->Release();
                fallbackIconTexture_ = nullptr;
            }
            if (appLogoTexture_ != nullptr)
            {
                appLogoTexture_->Release();
                appLogoTexture_ = nullptr;
            }
        }

