FROM mcr.microsoft.com/dotnet/aspnet:9.0-preview AS base
USER $APP_UID
WORKDIR /app
EXPOSE 8080
EXPOSE 8081

FROM mcr.microsoft.com/dotnet/sdk:9.0-preview AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src

# Install NativeAOT build prerequisites
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       clang zlib1g-dev

COPY ["FunExcitingDangerous/FunExcitingDangerous.csproj", "FunExcitingDangerous/"]
RUN dotnet restore "FunExcitingDangerous/FunExcitingDangerous.csproj"
COPY . .
WORKDIR "/src/FunExcitingDangerous"
RUN dotnet build "FunExcitingDangerous.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "FunExcitingDangerous.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=true

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "FunExcitingDangerous.dll"]
