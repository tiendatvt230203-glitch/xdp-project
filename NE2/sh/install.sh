#!/bin/bash

# Ngừng script nếu có lỗi xảy ra
set -e

echo "--- Đang bắt đầu quá trình cài đặt môi trường cho Network Encryptor ---"

# 1. Cập nhật danh sách gói phần mềm
sudo apt update

# 2. Cài đặt các công cụ biên dịch cơ bản
echo ">>> Cài đặt Build Tools (gcc, clang, llvm)..."
sudo apt install -y build-essential clang llvm pkg-config

# 3. Cài đặt các thư viện phát triển (Header files)
echo ">>> Cài đặt các thư viện bổ trợ (-dev)..."
sudo apt install -y \
    libelf-dev \
    libbpf-dev \
    libxdp-dev \
    libssl-dev \
    libpq-dev \
    postgresql-server-dev-all

# 4. Cài đặt Kernel Headers (Cực kỳ quan trọng cho XDP/eBPF)
echo ">>> Cài đặt Kernel Headers cho phiên bản hiện tại..."
sudo apt install -y linux-headers-$(uname -r)

# 5. Kiểm tra sự tồn tại của pg_config (để chắc chắn Makefile chạy được)
if ! command -v pg_config &> /dev/null
then
    echo "CẢNH BÁO: Không tìm thấy pg_config. Vui lòng kiểm tra lại cài đặt libpq-dev."
else
    echo "OK: pg_config đã sẵn sàng tại $(pg_config --includedir)"
fi

# 6. Tạo thư mục bin nếu chưa có (để tránh lỗi Makefile ở một số môi trường)
mkdir -p bin

echo "--- Hoàn tất cài đặt! ---"
echo "Bây giờ bạn có thể chạy: make all"
